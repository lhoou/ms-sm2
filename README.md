# ms-sm2
Implementation  of A SM2-based Multi-signature Scheme

## Test Result for 5 Parties

> Please Enter the Number of Parties:
> 
>     5
> 
> Key Generation for 5 Parties:
> 
> Please Input a UserID for Party 1
> vehicle1
> User1:vehicle1
> Public key:0404c98d6929c72ff1bd09ef818d9607bc28ffaf8bd76c63ab5ec85f418045a73ea4f7f5008c1b6ea0a1> e4b1ced79ee7ba1ab1d6a6cd0dc0addae7fe8359473184
 > Private Key:4da1857e4543c7a863b8ccdfa745639c7cdc24f6df9401c9de35d2b194e57e82
> 
> Please Input a UserID for Party 2
> vehicle2
> User2:vehicle2
 > Public key:043510750cf239ee5913dfe8c9798262f0bbcc8b8ad0c1c397491d0a183b625840c59c9c46972cd69> cf630d51584a8f55701f90eebfae4509ebf649bc54081c4fb
 > Private Key:7284fb9843972875a76b59d7922e22e80aa6f456e426dbf472566de085557900
> 
> Please Input a UserID for Party 3
>rsu1
> User3:rsu1
> Public key:043b75903d8e18075e9858f028794d651a11bae7f965e86f712257d7647452a3102facf6d91a2394c9f5495959837816236d650460853c9dcd4d09af9f27fa3d79
 > Private Key:6fb44f8572e5725b74844f407bf25411968b46b8d7e026e83e8a7ae59c59c09b
> 
> Please Input a UserID for Party 4
> rsu2
> User4:rsu2
 > Public key:04263ff2eb4d1eccc60a007b5517b89c04f3893fdb28e22ef09fe75f88f56dc6b27942bb81c7aa9c7d2b2b5db217eca17137e1ee46aeafb8e018d31a716be2a7c5
 > Private Key:2c0e8fd5df7816e46888b882b00a2b37faefbe7f20f9cb7d71f71b98cd34b0b6
> 
> Please Input a UserID for Party 5
> rsu3
> User5:rsu3
 > Public key:04e66477fa8e2e1db4e572cc30cd611587e3ad69028366dbd3032d1ab327d4e4a9de65f4019582896ad119fb5658fa8b684ae4fefca0bab88d02caea0adcd6329f
 > Private Key:74aa69248b42868535d7e6fddc400a208aca26852050908425d77306837f75ec
> 
> 
> Sining Process:
> 
> 
> The message to co-sign is:Traffic Jam!
> MessageInHex:54726166666963204a616d21
> 
> Randomness Chosen by Party1:
>04abfd065ce26a58010b6723c86d27e2979aabee1796875257a886b87dee8f253bf5f66a51142dd66d6ca9ad3a19588bac7cc0dce03bd7b77b73f0eb640be00a1a
> 88260416386511683802659822504318910573142187980547271000196817256757180553287
> 
> Randomness Chosen by Party2:
>04e88fd92baddeb0311f8cd96e42ed1a9f2d56b2bfbb639d6846e55fc62a6cacd485dfe5bd703bff695e247af360c301191c1225fcb32b3125b065d8d36d4afaa2
> 113552584841076056125765444463805193283438500540328358124792089195612174845714
> 
> Randomness Chosen by Party3:
>0480e5f7b52bf01f4ddec6cc63afdfc79ac9651826e427709451584ca1622f77ddfc87ed10326dcfea533d0b0e0ebcf27244549e29c69ed37a27b7973b1f32946f
> 82308410320065289353508864780660489199449292931231396537814623568744767823345

> Randomness Chosen by Party4:
>0491c1b057970fb47677f6a16e4193a116dbc346a075f2cc21ed55bf633e246c175ddb5733a084d4b87e3759a78e63ef306ffefdbe9102ff0c2f61aedd5992ba51
> 70652129330251035821006086576218672510466577324078139406228947962959500008298

> Randomness Chosen by Party5:
>045c16e1d688add865035b0666f34df635585e6ca3c9e69e6e0801219b80280a4537105af4e0c1cf52f7aea6d974c8d8296ae66cb378fc3329533fd60fb7311e88
> 48224464721618561685755130380801545908131750069257527477010508601875040151741

> Core Local Computation:416458ns
> Local signing time for user vehicle1 : 25731708ns

> Core Local Computation:109625ns
> Local signing time for user vehicle2 : 9263500ns

> Core Local Computation:194375ns
> Local signing time for user rsu1 : 6186417ns

> Core Local Computation:763042ns
> Local signing time for user rsu2 : 4575459ns

> Core Local Computation:1609709ns
> Local signing time for user rsu3 : 15657292ns
> 
> Simulated Co-sining Time:1379333ns
> 
> >
> The Multi-signature is:
>3082016c022100dd8d975fe4924ca692881b884fbf7aca28fe9ffae965831e66311ac21daf9c790282014504abfd065ce26a58010b6723c86d27e2979aabee1796875257a886b87dee8f253bf5f66a51142dd66d6ca9ad3a19588bac7cc0dce03bd7b77b73f0eb640be00a1a04e88fd92baddeb0311f8cd96e42ed1a9f2d56b2bfbb639d6846e55fc62a6cacd485dfe5bd703bff695e247af360c301191c1225fcb32b3125b065d8d36d4afaa20480e5f7b52bf01f4ddec6cc63afdfc79ac9651826e427709451584ca1622f77ddfc87ed10326dcfea533d0b0e0ebcf27244549e29c69ed37a27b7973b1f32946f0491c1b057970fb47677f6a16e4193a116dbc346a075f2cc21ed55bf633e246c175ddb5733a084d4b87e3759a78e63ef306ffefdbe9102ff0c2f61aedd5992ba51045c16e1d688add865035b0666f34df635585e6ca3c9e69e6e0801219b80280a4537105af4e0c1cf52f7aea6d974c8d8296ae66cb378fc3329533fd60fb7311e88
> 
> Verification Process:
> 
> Verfication Time:20916625ns
> 
> Is the multi-signature Valid:
> true
