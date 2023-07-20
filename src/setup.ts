// Copyright 2023 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as core from '@actions/core';
import {
  downloadTool,
  extractTar,
  extractZip,
  cacheDir
} from '@actions/tool-cache';
import {getOctokit} from '@actions/github';
import * as toml from 'smol-toml';

type Gcs = {
  bucket: string;
  read_only: boolean;
};

async function setup() {
  let version = core.getInput('version');
  if (version.length === 0) {
    // If no version is specified, the latest version is used by default.
    const token = core.getInput('token', {required: true});
    const octokit = getOctokit(token);
    const release = await octokit.rest.repos.getLatestRelease({
      owner: 'mozilla',
      repo: 'sccache'
    });
    version = release.data.tag_name;
  }

  let gcs: Gcs | null = null;
  if (core.getBooleanInput('use_gcs')) {
    const bucket = core.getInput('gcs_bucket');
    const read_only = core.getBooleanInput('gcs_read_only');
    gcs = {bucket, read_only};
    core.info(`using gcs ${bucket}, ${read_only}`);
  }

  core.info(`try to setup sccache version: ${version}`);

  const filename = get_filename(version);
  const dirname = get_dirname(version);

  const download_url = `https://github.com/mozilla/sccache/releases/download/${version}/${filename}`;
  const sha256_url = `${download_url}.sha256`;
  core.info(`sccache download from url: ${download_url}`);

  // Download and extract.
  const sccache_pkg = await downloadTool(download_url);
  const sha256_file = await downloadTool(sha256_url);

  // Calculate the SHA256 checksum of the downloaded file.
  const fileBuffer = await fs.promises.readFile(sccache_pkg);
  const hash = crypto.createHash('sha256');
  hash.update(fileBuffer);
  const checksum = hash.digest('hex');

  // Read the provided checksum from the .sha256 file.
  const checksum_file = (await fs.promises.readFile(sha256_file))
    .toString()
    .trim();

  // Compare the checksums.
  if (checksum !== checksum_file) {
    core.setFailed('Checksum verification failed');
    return;
  }
  core.info(`Correct checksum: ${checksum}`);

  let sccache_extracted_to;
  if (get_extension() == 'zip') {
    sccache_extracted_to = await extractZip(sccache_pkg);
  } else {
    sccache_extracted_to = await extractTar(sccache_pkg);
  }
  core.info(`sccache extracted to: ${sccache_extracted_to}`);

  // Cache sccache.
  const sccache_home = await cacheDir(
    `${sccache_extracted_to}/${dirname}`,
    'sccache',
    version
  );
  core.info(`sccache cached to: ${sccache_home}`);

  // Add cached sccache into path.
  core.addPath(`${sccache_home}`);
  // Expose the sccache path as env.
  const sccache_path = `${sccache_home}/sccache`;
  core.exportVariable('SCCACHE_PATH', sccache_path);

  if (gcs) {
    await write_gcs_config(gcs);
  } else {
    // Expose the gha cache related variable to make users easier to
    // integrate with gha support.
    core.exportVariable(
      'ACTIONS_CACHE_URL',
      process.env.ACTIONS_CACHE_URL || ''
    );
    core.exportVariable(
      'ACTIONS_RUNTIME_TOKEN',
      process.env.ACTIONS_RUNTIME_TOKEN || ''
    );
  }

  await write_cargo_config(sccache_path);
}

async function write_gcs_config(gcs: Gcs) {
  // write gcs info into sccache config
  let sccache_conf_path = `${os.homedir()}/.config/sccache/config`;
  await fs.promises.mkdir(path.dirname(sccache_conf_path), {recursive: true});

  core.info(`writing gcs config to ${sccache_conf_path}`);
  await fs.promises.writeFile(
    sccache_conf_path,
    toml.stringify({
      cache: {
        gcs: {
          rw_mode: gcs.read_only ? 'READ_ONLY' : 'READ_WRITE',
          bucket: gcs.bucket,
          key_prefix: '_sccache'
        }
      }
    }),
    'utf-8'
  );
}

async function write_cargo_config(sccache_path: string) {
  // write `rustc_wrapper` into cargo config
  const cargo_conf_path = `${os.homedir()}/.cargo/config.toml`;
  await fs.promises.mkdir(path.dirname(cargo_conf_path), {recursive: true});
  const conf_exists = await file_exists(cargo_conf_path);
  let cargo_conf: any;
  if (conf_exists) {
    const input = await fs.promises.readFile(cargo_conf_path, 'utf-8');
    cargo_conf = toml.parse(input);
  } else {
    cargo_conf = {};
  }
  cargo_conf['build'] = {
    ...(cargo_conf['build'] ?? {}),
    ['rustc-wrapper']: sccache_path
  };
  const output = toml.stringify(cargo_conf);
  await fs.promises.writeFile(cargo_conf_path, output, 'utf-8');
}

async function file_exists(file: string) {
  try {
    await fs.promises.access(file, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function get_filename(version: string): Error | string {
  return `sccache-${version}-${get_arch()}-${get_platform()}.${get_extension()}`;
}

function get_dirname(version: string): Error | string {
  return `sccache-${version}-${get_arch()}-${get_platform()}`;
}

function get_arch(): Error | string {
  switch (process.arch) {
    case 'x64':
      return 'x86_64';
    case 'arm64':
      return 'aarch64';
    default:
      return Error('Unsupported arch "${process.arch}"');
  }
}

function get_platform(): Error | string {
  switch (process.platform) {
    case 'darwin':
      return 'apple-darwin';
    case 'win32':
      return 'pc-windows-msvc';
    case 'linux':
      return 'unknown-linux-musl';
    default:
      return Error('Unsupported platform "${process.platform}"');
  }
}

function get_extension(): string {
  switch (process.platform) {
    case 'win32':
      return 'zip';
    default:
      return 'tar.gz';
  }
}

setup().catch(err => {
  core.error(err);
  core.setFailed(err.message);
});
