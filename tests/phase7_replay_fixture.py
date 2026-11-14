"""Synthetic Phase 7 replay, not research evidence. Reward excluded from event hash.

World and ordered actions: test_phase7_environment_contract.world/TRACE.
Capacities: 16 nodes, 4 vulnerabilities, 30 steps. Float32 native-byte hashes
are pinned for the current little-endian test platform; JSON hashes are canonical.
"""

RESET_SEED = 7
TOPOLOGY_SHA = "7d651a33b946b30e72ec7027b3d47bae2e97c9e374b35a4377bd80208f8b1fa5"
_ROWS = (
    (
        "3cfb8bdc8596424756ea984758bcef73d9668aaae0f49d49c744b432b7f3b733",
        "374c7f96717942d489bad3a23f7e2a601b6e5977d12879c0af7fb5c5f91e1f58",
        None,
    ),
    (
        "b8341e7e7a3ce9b9f200ccc92a1932edc029a180738283ff223bd3e526aeccf5",
        "5f843f4b2d6f4bafa8494113c7e2393c3a5f9566c644c2606f0e5d6f57c57a19",
        "6b5d87cdec88fe1ed7f2601a7a7fa4f804fe5c357df4db6a4cd96c8b8d5b8ab1",
    ),
    (
        "915865168e7133d95bac605f800b6fd489f88170e56e21eb2855b9b9999087f2",
        "e043515dbb0baa524eb468f93d49a7522d24510d83dec693245a9506cab53515",
        "2e3b3a126b0c74129726475b5a6021adc23d74ee993eacc341c1f666c50900b9",
    ),
    (
        "b860587c608b973d49a6c63307ee98aaeac44eef0290eac3ec029f46d5564283",
        "e714b504e891ffd94456e24244313102dbd56f7893d6fa679c2e2614044a279f",
        "0c7ffa4fa5e41d72a86962ca5f51838f12898013ca583d72b47bb8729202411f",
    ),
    (
        "32ef1c42a7eb20001e04a1b543e5d6127b1b29d31239b52a2a7509e3a498fffb",
        "a2c5935e5716ac47faaf57a4356596a6272b759f67d6f974b48c7284ab02b282",
        "bb2e9e4df5cf3291601f141644dd89083909cf1c464cbc146c6146b4ffddec50",
    ),
    (
        "b953166d2e86a89918bea1c8822d91f09d600096dc8f5aac99378d74b4478bdf",
        "f5bf268dbb680ef2a489c08309e95d4cf8e8aa133017d4225d92b370c073bb05",
        "477dbf188f8759d9f8568634c53a037c2968f71c037246b29462bb0e310f76a9",
    ),
    (
        "a7662ea81a90c392932f7150739f82df62f8b4ff5bda4e46184b239bf33addf9",
        "05d50e293af7b240646a00a4998b716b3430d1e413be1b6c88e1dae1cf6bb0b1",
        "a4806582b98b33ebdc22a51368a6b730718c42676a850a2220f9379e55a720fd",
    ),
    (
        "182ca52e03ad7fb7963405631bc0fdf07cbddd2f3517b15c30fd712493240915",
        "21b502e160709df0f75a9650a5e90f9b9e6a546574c7c9b2363692af7a492b10",
        "43af0d79bbb7b7ed90143410333c0d82fd96e5d8112a5ed65f63913ba42e9e15",
    ),
    (
        "3934375c663a02ed985769768773491c7f2486c7fd5f20672ade39fb65b9d2d1",
        "d511df2a57092cfec9d15a337792a2a3bb219f6fc69f309d23950fa83f41b2cf",
        "f1d569a1f600561d4130830986615dc7d2b293c0ff6dee8a93d743b1d119d849",
    ),
    (
        "4e35590e19472b38c1a4cc7457ddf3491a03b9d0c92069d0af44bd144d694153",
        "9108dde8a0e74541e3f420b85a8420f4e4187c45067a8ca38cdbbc4c07543829",
        "6a93f44466443b583b76d957d956369ce95eb63aa2bb0c2a704f84f3f9d8492b",
    ),
    (
        "fdf9566c9dd3bb6bbd987f458146fad4f8778fbb3dca8a06bf891dfce9f61316",
        "ab5370d178927155dcdca7dac91808c5879d130f4333f0a53e18e1704d789f7a",
        "57b178a5a2459934e92ed7deb46b25249f5fbc322ebdea8147ef2ef15d9f31fa",
    ),
    (
        "f96e72217f36ad8a9eacfd050a6dc07d0917be5302e2885967f6dbe458ac2f14",
        "304684af443d8c956014b1a1ffd1ed0b91b910e4fc15d5c4bc56988e29f2895d",
        "3906d22749eb3f7667946888df29a26c32ebdf9ae782ff2be329653cdbf16406",
    ),
    (
        "575d0b3894f3a1d89e2d6c6dc0ba118bf3ca7616d27ec09418cdf52587ede30a",
        "d0426e55a4cc01a95e966ef378c565fb09012dd6ae25852ccd7c601d4a768c04",
        "3b536062076ad7eed80069a680c128d7527d1041444ac1a999348bade48fb413",
    ),
    (
        "177e9777cb2cdae1f811577a8f8ee359a176cba6f38ff3a6246b75b3287b40e3",
        "ec3d3c6b098f52427cc40e4e2771e28b7578a0144a133a60b262c74ade4664b7",
        "7d4df0a34bb2ae76a7d6c3482964ad9fa4f8660a103b732e24dd7459c92d7198",
    ),
)
EXPECTED = [
    {
        "observation": observation,
        "knowledge": knowledge,
        **(
            {"event": event, "terminated": index == len(_ROWS) - 1, "truncated": False}
            if event
            else {}
        ),
    }
    for index, (observation, knowledge, event) in enumerate(_ROWS)
]
