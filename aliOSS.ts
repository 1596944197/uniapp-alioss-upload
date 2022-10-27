import { getOssConfig } from '@/api/sys/SysAPI'; // 获取后台返回sts信息,该接口必须返回accessKeyId, accessKeySecret, bucket, stsToken, region这几个字段
import crypto from 'crypto-js';
import { Base64 } from 'js-base64';

export function getAliToken(): Promise<any> {
  // 获取Token
  return new Promise((resolve, reject) => {
    getOssConfig()
      .then((res) => {
        if (res!.code === 200) {
          const { accessKeyId, accessKeySecret, bucket, stsToken, region, ...args } = res!.data;
          const dataObj = {
            region,
            bucket,
            accessKeyId,
            accessKeySecret,
            stsToken,
          };
          resolve(dataObj);
        } else {
          reject(false);
        }
      })
      .catch((err) => {
        console.log(err);
      });
  });
}
/**
 *
 * @param {*} filename
 * @param {*} file
 * @returns fileUrl
 */
export async function updateAliOSS(filename: string, path: string): Promise<{ name; extname; url }> {
  let params: any = {};

  const response = await getAliToken(); // 获取oss对象所需参数赋值params
  if (!response) return Promise.reject('获取oss失败');
  params = response;
  return new Promise((resolve, reject) => {
    uploadFile(params).then(resolve).catch(reject);
  });

  async function uploadFile(params: {
    region: string;
    bucket: string;
    accessKeyId: string;
    accessKeySecret: string;
    stsToken: '';
  }): Promise<{ name; extname; url }> {
    const date = new Date();
    date.setHours(date.getHours() + 1);
    const policyText = {
      expiration: date.toISOString(), // 设置policy过期时间。
      conditions: [
        // 限制上传大小。
        ['content-length-range', 0, 1024 * 1024 * 1024],
      ],
    };
    const policy = Base64.encode(JSON.stringify(policyText)); // policy必须为base64的string。
    const signature = computeSignature(params.accessKeySecret, policy);

    return new Promise((resolve, reject) => {
      uni.uploadFile({
        url: `https://${`${params.bucket}`}.${params.region}.aliyuncs.com`,
        name: 'file',
        filePath: path,
        formData: {
          key: filename,
          ossAccessKeyId: params.accessKeyId,
          signature,
          policy,
          'x-oss-security-token': params.stsToken,
          success_action_status: '200',
        },
        success(res) {
          if (res.statusCode === 200) {
            return resolve({
              name: filename,
              extname: filename.split('.')[1],
              url: `https://${`${params.bucket}`}.${params.region}.aliyuncs.com/${filename}`,
            });
          }
          reject('上传失败');
        },
        fail(error) {
          reject(error);
        },
      });
    });
  }
}

// 随机字符串
function randomString(num) {
  const chars = [
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
  ];
  let res = '';
  for (let i = 0; i < num; i++) {
    const id = Math.ceil(Math.random() * 35);
    res += chars[id];
  }
  return res;
}
// 计算签名。
function computeSignature(accessKeySecret, canonicalString) {
  return crypto.enc.Base64.stringify(crypto.HmacSHA1(canonicalString, accessKeySecret));
}
