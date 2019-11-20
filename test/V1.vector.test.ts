import { V1Deprecated, PublicKey, SymmetricKey } from '../src/';

describe('Protocol V1 Test Vectors', () => {
  const v1 = new V1Deprecated() as any;

  describe('V1 Official Test Vectors', () => {
    // NOTE: Throughout these tests we use the undocumented __encrypt API, allowing us to
    //       provide custom nonce parameters, needed for aligning with known test vectors.

    let symmetricKey: SymmetricKey, nonce1: Buffer, nonce2: Buffer, publicKey: PublicKey;

    beforeEach(async () => {
      const rawSymmetricKey = Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex');
      symmetricKey = SymmetricKey.V1Deprecated();
      await symmetricKey.inject(rawSymmetricKey);

      nonce1 = Buffer.alloc(32).fill(0);
      nonce2 = Buffer.from('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2', 'hex');

      const rawPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p5GHgwoGW
wz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwx
KheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1
Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAA
pVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6al
UyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8
owIDAQAB
-----END PUBLIC KEY-----`;
      publicKey = PublicKey.V1Deprecated();
      await publicKey.inject(rawPublicKey);
    });

    it('Test Vector 1-E-1', async () => {
      // given
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' });

      //when
      const token = await v1.encryptWithNonce(message, symmetricKey, '', nonce1);

      // then
      const expectedToken =
        'v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8';
      expect(token).toBe(expectedToken);
    });

    it('Test Vector 1-E-2', async () => {
      // given
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' });

      //when
      const token = await v1.encryptWithNonce(message, symmetricKey, '', nonce1);

      // then
      const expectedToken =
        'v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkRGlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzkMr1RvfDI8emoPoW83q4Q60_xpHaw';
      expect(token).toBe(expectedToken);
    });

    it('Test Vector 1-E-3', async () => {
      // given
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' });

      //when
      const token = await v1.encryptWithNonce(message, symmetricKey, '', nonce2);

      // then
      const expectedToken =
        'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg';
      expect(token).toBe(expectedToken);
    });

    it('Test Vector 1-E-4', async () => {
      // given
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' });

      //when
      const token = await v1.encryptWithNonce(message, symmetricKey, '', nonce2);

      // then
      const expectedToken =
        'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbHXUTWXchFEi0etJ4u6tqgxZSklcec';
      expect(token).toBe(expectedToken);
    });

    it('Test Vector 1-E-5', async () => {
      // given
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' });
      const footer = JSON.stringify({ kid: 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo' });

      //when
      const token = await v1.encryptWithNonce(message, symmetricKey, footer, nonce2);

      // then
      const expectedToken =
        'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9';
      expect(token).toBe(expectedToken);
    });

    it('Test Vector 1-E-6', async () => {
      // given
      const message = JSON.stringify({ data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' });
      const footer = JSON.stringify({ kid: 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo' });

      //when
      const token = await v1.encryptWithNonce(message, symmetricKey, footer, nonce2);

      // then
      const expectedToken =
        'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9';
      expect(token).toBe(expectedToken);
    });

    it('Test Vector 1-S-1', async () => {
      // given
      const token =
        'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5kiAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEtm2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJzVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96SfQ6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtpflZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw';

      // when
      const verified = await v1.verify(token, publicKey, '');

      // then
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' });
      expect(verified).toBe(message);
    });

    it('Test Vector 1-S-2', async () => {
      //given
      const token =
        'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9';
      const footer = JSON.stringify({ kid: 'dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn' });

      // when
      const verified = await v1.verify(token, publicKey, footer);

      // then
      const message = JSON.stringify({ data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' });
      expect(verified).toBe(message);
    });
  });

  describe('#1E - authenticated encryption', () => {
    // NOTE: Throughout these tests we use the undocumented __encrypt API, allowing us to
    //       provide custom nonce parameters, needed for aligning with known test vectors.

    let symmetricKey: SymmetricKey, nullSymmetrickey: SymmetricKey, fullSymmetricKey: SymmetricKey, nonce: Buffer;

    beforeEach(async () => {
      const rawSymmetricKey = Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex');
      symmetricKey = SymmetricKey.V1Deprecated();
      await symmetricKey.inject(rawSymmetricKey);

      const rawNullSymmetrickey = Buffer.alloc(32).fill(0);
      nullSymmetrickey = SymmetricKey.V1Deprecated();
      await nullSymmetrickey.inject(rawNullSymmetrickey);

      const rawFullSymmetricKey = Buffer.alloc(32).fill(255, 0, 32);
      fullSymmetricKey = SymmetricKey.V1Deprecated();
      await fullSymmetricKey.inject(rawFullSymmetricKey);
    });

    describe('#1', () => {
      beforeEach(() => {
        nonce = Buffer.alloc(32).fill(0);
      });

      it('#1 - Test Vector 1E-1-1', async () => {
        // when
        const token = await v1.encryptWithNonce('', nullSymmetrickey, '', nonce);

        // then
        const expectedToken =
          'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXyNMehtdOLJS_vq4YzYdaZ6vwItmpjx-Lt3AtVanBmiMyzFyqJMHCaWVMpEMUyxUg';
        expect(token).toBe(expectedToken);
      });

      it('#2 - Test Vector 1E-1-2', async () => {
        // when
        const token = await v1.encryptWithNonce('', fullSymmetricKey, '', nonce);

        // then
        const expectedToken =
          'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTWgetvu2STfe7gxkDpAOk_IXGmBeea4tGW6HsoH12oKElAWap57-PQMopNurtEoEdk';
        expect(token).toBe(expectedToken);
      });

      it('#3 - Test Vector 1E-1-3', async () => {
        // when
        const token = await v1.encryptWithNonce('', symmetricKey, '', nonce);

        // then
        const expectedToken =
          'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTV8OmiMvoZgzer20TE8kb3R0QN9Ay-ICSkDD1-UDznTCdBiHX1fbb53wdB5ng9nCDY';
        expect(token).toBe(expectedToken);
      });
    });

    describe('#2', () => {
      beforeEach(() => {
        nonce = Buffer.alloc(32).fill(0);
      });

      it('#1 - Test Vector 1E-2-1', async () => {
        // when
        const token = await v1.encryptWithNonce('', nullSymmetrickey, 'Cuon Alpinus', nonce);

        // then
        const expectedToken =
          'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVhyXOB4vmrFm9GvbJdMZGArV5_10Kxwlv4qSb-MjRGgFzPg00-T2TCFdmc9BMvJAA.Q3VvbiBBbHBpbnVz';
        expect(token).toBe(expectedToken);
      });

      it('#2 - Test Vector 1E-2-2', async () => {
        // when
        const token = await v1.encryptWithNonce('', fullSymmetricKey, 'Cuon Alpinus', nonce);

        // then
        const expectedToken =
          'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVna3s7WqUwfQaVM8ddnvjPkrWkYRquX58-_RgRQTnHn7hwGJwKT3H23ZDlioSiJeo.Q3VvbiBBbHBpbnVz';
        expect(token).toBe(expectedToken);
      });

      it('#3 - Test Vector 1E-2-3', async () => {
        // when
        const token = await v1.encryptWithNonce('', symmetricKey, 'Cuon Alpinus', nonce);

        // then
        const expectedToken =
          'v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTW9MRfGNyfC8vRpl8xsgnsWt-zHinI9bxLIVF0c6INWOv0_KYIYEaZjrtumY8cyo7M.Q3VvbiBBbHBpbnVz';
        expect(token).toBe(expectedToken);
      });
    });

    describe('#3', () => {
      beforeEach(() => {
        nonce = Buffer.alloc(32).fill(0);
      });

      it('#1 - Test Vector 1E-3-1', async () => {
        // when
        const token = await v1.encryptWithNonce('Love is stronger than hate or fear', nullSymmetrickey, '', nonce);

        // then
        const expectedToken =
          'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA45LtwQCqG8LYmNfBHIX-4Uxfm8KzaYAUUHqkxxv17MFxsEvk-Ex67g9P-z7EBFW09xxSt21Xm1ELB6pxErl4RE1gGtgvAm9tl3rW2-oy6qHlYx2';
        expect(token).toBe(expectedToken);
      });

      it('#2 - Test Vector 1E-3-2', async () => {
        // when
        const token = await v1.encryptWithNonce('Love is stronger than hate or fear', fullSymmetricKey, '', nonce);

        // then
        const expectedToken =
          'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47lQ79wMmeM7sC4c0-BnsXzIteEQQBQpu_FyMznRnzYg4gN-6Kt50rXUxgPPfwDpOr3lUb5U16RzIGrMNemKy0gRhfKvAh1b8N57NKk93pZLpEz';
        expect(token).toBe(expectedToken);
      });

      it('#3 - Test Vector 1E-3-3', async () => {
        // when
        const token = await v1.encryptWithNonce('Love is stronger than hate or fear', symmetricKey, '', nonce);

        // then
        const expectedToken =
          'v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47hvAicYf1zfZrxPrLeBFdbEKO3JRQdn3gjqVEkR1aXXttscmmZ6t48tfuuudETldFD_xbqID74_TIDO1JxDy7OFgYI_PehxzcapQ8t040Fgj9k';
        expect(token).toBe(expectedToken);
      });
    });

    describe('#4', () => {
      beforeEach(() => {
        nonce = Buffer.from('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2', 'hex');
      });

      it('#1 - Test Vector 1E-4-1', async () => {
        // when
        const token = await v1.encryptWithNonce('Love is stronger than hate or fear', nullSymmetrickey, 'Cuon Alpinus', nonce);

        // then
        const expectedToken =
          'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYbivwqsESBnr82_ZoMFFGzolJ6kpkOihkulB4K_JhfMHoFw4E9yCR6ltWX3e9MTNSud8mpBzZiwNXNbgXBLxF_Igb5Ixo_feIonmCucOXDlLVUT.Q3VvbiBBbHBpbnVz';
        expect(token).toBe(expectedToken);
      });

      it('#2 - Test Vector 1E-4-2', async () => {
        // when
        const token = await v1.encryptWithNonce('Love is stronger than hate or fear', fullSymmetricKey, 'Cuon Alpinus', nonce);

        // then
        const expectedToken =
          'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYZ8rQTA12SNb9cY8jVtVyikY2jj_tEBzY5O7GJsxb5MdQ6cMSnDz2uJGV20vhzVDgvkjdEcN9D44VaHid26qy1_1YlHjU6pmyTmJt8WT21LqzDl.Q3VvbiBBbHBpbnVz';
        expect(token).toBe(expectedToken);
      });

      it('#3 - Test Vector 1E-4-3', async () => {
        // when
        const token = await v1.encryptWithNonce('Love is stronger than hate or fear', symmetricKey, 'Cuon Alpinus', nonce);

        // then
        const expectedToken =
          'v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz';
        expect(token).toBe(expectedToken);
      });
    });
  });

  describe.skip('#1S - signing', () => {});
});
