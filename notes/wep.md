> Historical lab notes; screenshots and identifiers omitted.

# Lab 3 (Breaking WEP) — Report

**Group**: T16A_05

**Members**:

STUDENT_ID - Shaoran LIU

STUDENT_ID - Jiawei Dong  

---

## Q1 What is the purpose of the 24-bit Initialization Vector (IV) in WEP?

**Answer:**  
The main purpose of the IV in WEP is to improve confidentiality, make sure that the same shared key does not generate the same RC4 keystream for every packet. In WEP, the IV is combined with the shared secret key to form the per-packet RC4 key input. This means that even when the same WEP key is reused, different packets can still be encrypted with different keystreams. In short, the IV is intended to add per-packet variation and reduce direct keystream reuse.

---

## Q2 Why does the small IV size create a security vulnerability?

**Answer:**  
WEP uses only a 24-bit IV, so the total IV space is very small: \(2^{24}\) possible values. In a busy network, IV values are reused relatively quickly. Once IV reuse occurs, different packets may be encrypted under the same RC4 keystream. This creates statistical patterns that attackers can exploit. Over time, by collecting many packets with many IVs, an attacker can use attacks such as the FMS-style statistical approach implemented in Aircrack-ng to recover the WEP key.

---

## Q3 During the lab, you captured wireless packets using Airmon-ng. What type of information in the captured packets is required to recover the WEP key?

**Answer:**  
The attacker needs a large number of captured WEP-encrypted packets containing:

1. **The IV values** used by the AP.  
2. **The corresponding encrypted payloads**, especially traffic with predictable structure.  
3. In practice, packets such as **ARP frames** are especially useful because their contents are partly predictable, making them ideal for statistical analysis and replay-based traffic generation. (Acutally, during the lab, the ARP packets were hard to capture. We can only keep disconnecting and reconnecting our mobile phones, refreshing the web page, and then the ARP messages will be added a few more times. )

[Original screenshot omitted from this review copy.]

The lab instructions also indicate that the capture file created by `airodump-ng` is later reused by `aircrack-ng` for key recovery.

[Original screenshot omitted from this review copy.]

[Original screenshot omitted from this review copy.]

---

## Q4 Why must an attacker collect a large number of IVs before attempting to recover a WEP key?

**Answer:**  
A large number of IVs is required because WEP key recovery is a **statistical attack**, not a direct brute-force attack against the full key space. Each captured packet contributes only a small amount of useful information. The attacker needs many packets so that statistical biases in RC4 key scheduling become strong enough to reveal the correct key bytes. Therefore, the more IVs collected, the more reliable the key-voting process becomes, and the higher the chance that `aircrack-ng` can recover the correct WEP key.

---

## Q5 How many IVs did you record before Aircrack-ng could recover the key? Provide a screenshot of your lab work.

**Answer:**  
Aircrack-ng recovered the WEP key after **11364 IVs**.. 

[Original screenshot omitted from this review copy.]

---

## Q6 What measures did you take during the lab to speed up the encrypted traffic generation from the WEP AP?

**Answer:**  
To speed up encrypted traffic generation, I used an **ARP replay attack** together with repeated client activity:

1. I started `aireplay-ng --arpreplay` using the target AP’s BSSID and the connected station MAC address.  
2. I opened the local login page hosted on the Raspberry Pi at `https://lab.example.invalid` (or `https://lab.example.invalid` if needed).  
3. I refreshed the page and, when necessary, disconnected and reconnected the phone to trigger fresh ARP traffic.  (more ARP much quicker)
4. Once an ARP request was captured, `aireplay-ng` replayed it repeatedly, which rapidly increased the number of encrypted packets and IVs collected.

Some guess: Why this ARP packets are rare? Maybe because the browser has a protection or firewall settings have influenced it…. 

---

## Q7 Explore the use of tool macchanger in Kali Linux. What steps would you take to perform MAC spoofing (configuring your MAC to be the same as another station)?

**Answer:**  
To perform MAC spoofing using `macchanger`, I would follow these steps:

1.Bring the interface down:

```bash
sudo ip link set wlan0 down
```

2.Change the MAC address to the target station’s MAC:

```
sudo macchanger --mac <target-station-mac> wlan0
```

3.Bring the interface back up:

```
sudo ip link set wlan0 up
```

4.Verify the new MAC address:

```
ip link show wlan0
```

or

```
macchanger -s wlan0
```

If monitor mode is needed afterwards, I would then re-enable monitor mode using `airmon-ng start wlan0`.

------

## Q8 Suppose you capture IVs at the rate of 1500 IVs per second. What is the time you need to wait to detect IV reuse in the worst-case scenario?

**Answer:**

The WEP IV is 24 bits long, so the total number of possible IVs is:

2^24 = 16,777,216

In the worst-case scenario, IV reuse would only occur after all possible IVs have been used once.

Therefore, the required time is:

16,777,216 / 1500 = 11,184.81 seconds

Converting to hours:

11,184.81 / 3600 ≈ 3.11 hours

So the waiting time in the worst case is approximately **11,185 seconds**, or about **3.1 hours**.

------

## Q9 If a WEP key is 128 bits long, can an attacker still recover it quickly?

**Answer:**
Yes. Even if the WEP key is described as “128-bit WEP,” an attacker can still recover it quickly because the attack is **not** a brute-force attack against the full nominal key length. Instead, the attack exploits weaknesses in WEP itself:

- RC4 key scheduling weaknesses
- The very small 24-bit IV space (IV is still small)
- Frequent IV reuse
- Statistical leakage from large numbers of captured packets

So the practical weakness comes from the **protocol design**, not from trying every possible 128-bit key.

------

## Q10 Identify two major improvements introduced in WPA or WPA2 that address the weaknesses of WEP.

**Answer:**
 Two major improvements introduced in WPA/WPA2 are:

1. **Stronger encryption and better per-packet protection**
    WEP uses RC4 with a weak IV design, while WPA/WPA2 replaced this with much stronger mechanisms. WPA introduced TKIP as an intermediate improvement, and WPA2 introduced **AES-CCMP**, which provides much stronger confidentiality and integrity protection.
2. **Improved key management and integrity protection**
    WPA/WPA2 use a proper key establishment process such as the **4-way handshake**, instead of WEP’s static weak design. They also provide stronger integrity protection, preventing the kinds of forgery and statistical attacks that are possible in WEP.

The lab sheet explicitly notes that WEP was replaced by stronger protocols such as WPA, WPA2 and WPA3 because WEP’s small IV space and RC4-based design allow practical key recovery.
