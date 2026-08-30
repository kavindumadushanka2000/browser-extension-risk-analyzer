import csv
from analyzer import (
    load_manifest, collect_js_source, analyze_permissions,
    categorize_permissions, check_sensitive_sites, build_features, FEATURE_NAMES
)

EXTENSIONS_TO_ANALYZE = [
    # ---- keep any of your existing paths here if you want them included too ----

    # Adblock Plus - free ad blocker
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\cfhdojbkjhnklbpkdaibdccddilifddb\4.43.3_0",
    # Adobe Acrobat:PDF edit,convert,sign tools
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\efaidnbmnnnibpcajpcglclefindmkaj\26.8.2.1_0",
    # Ahrefs SEO Toolbar
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hgmoccdbjhknikckedaaebbpdeebhiei\3.2.10_0",
    # AI Grammar and Spell Checker by Ginger
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\kdfieneakcjfaiglcfcgkidlkmlijjnh\2.15.357_0",
    # AI Grammar Checker & Paraphraser – LanguageTool
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\oldceeleldhonbafppcapldpdifcinji\11.2.3_0",
    # AI Web Clipper - Pocket Alternative, Save & Read Later
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\odploolgnnjmefgcheaechhldnklfdnp\1.0.1_0",
    # Awesome Screen Recorder & Screenshot
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\nlipoenfbbikpbjkfpfillcgkoblgpmj\4.4.43_0",
    # Bitwarden Password Manager
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\nngceckbapebfimnlniiiahkandclblb\2026.8.0_0",
    # Boomerang for Gmail
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\mdanidgdpmkimeiiojknlnekblgmpdll\1.9.4_0",
    # Buffer
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\noojglkidnpfjbincgijbaiedldjfbhh\6.0.27_0",
    # Checker Plus for Gmail
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\oeopbcgkkoapgobdbedcemjljbihmemj\36.4_0",
    # Checker Plus for Google Calendar
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hkhggnncdpfibdhinjiegagmopldibha\46.1.1_0",
    # Clipboard Manager and Text Expander - Clipboard History Pro
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ajiejmhbejpdgkkigpddefnjmgcbkenk\3623_0",
    # Clockify Time Tracker
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pmjeegjhjdlccodhacdgbgfagbpmccpe\2.12.7_0",
    # ColorZilla
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\bhlhnicpbhignbdhedgjhgdocnmhomnp\4.1_0",
    # Dark Mode for All Websites
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\bkkmebacdnlpmchodmppoiidldonbjik\0.0.1_0",
    # Decentraleyes
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ldpochfccmkkmhdbclfhpagapcfdljkj\3.0.2_0",
    # DocHub - Sign PDF from Gmail
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\mjgcgnfikekladnkhnimljcalfibijha\2.4.0_0",
    # Download Twitter videos
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\gafbfkfkcfogdbcpannaipilhnjbbebd\5.0.2_0",
    # DuckDuckGo Search & Tracker Protection
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\bkdgflcldnnnapblkhphbgpggdiikppg\2026.8.6_0",
    # D'CENT Wallet – Hardware-Secured Extension
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pehjmcpnbaogigbginlmkcmjgeiiggng\1.0.17_0",
    # Ecommerce Image Downloader
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\oiaoeonjapnkifnhofdkgiohaieebokn\2.9.4_0",
    # Enhancer for YouTube
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ponfpcnoihfmfllpaingbgckeeldkhle\3.0.19_0",
    # Evernote Web Clipper
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pioclpoplcdbaefihamjohnefbikjilc\7.41.1_0",
    # Eye Dropper
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hmdcmlfkchdmnmnmheododdhjedfccka\4.10.3.17_0",
    # Font Finder
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\bhiichidigehdgphoambhjbekalahgha\0.6.5_0",
    # Forest: stay focused, be present
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\kjacjjdnoddnpbbcjilcajfhhbdhkpgk\6.5.0_0",
    # Free VPN - Super Fast Unlimited VPN Proxy for Chrome
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\cppljodbhecoilefippjhdbekghdigae\1.1.8_0",
    # Free VPN For Chrome - VPN Extension – Windscribe
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hnmpcagpplmpfojmgmnngilcnanddlhb\4.2.9_0",
    # Full Page Screen Capture
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pmabjgjpcbofkbbeiphkiaanogobokgg\3.15.18_0",
    # Ghostery AdBlocker for Privacy
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\mlomiejdfkolichcflejclcbmpeaniij\10.5.58_0",
    # Google Docs Offline
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi\1.109.1_0",
    # Google Keep Chrome Extension
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\lpcaedmchfhocbbapmcbpinfpgnhiddi\4.26341.540.1_0",
    # Google Translate
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\aapbdbdomjkkjkaonfhkkikfgjllcleb\2.0.17_0",
    # Grammarly: AI Writing Assistant and Grammar Checker App
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\kbfnbcaeplbcioakkpcpgfkobkghlhen\14.1324.0_0",
    # High Contrast
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\djcfdncoelnlbldjfhinnjlhdjlikmph\1.0.0_0",
    # Honey Search Protection
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\kaagccfaeapfijdjdjmdfjbgfelniaoc\3.3.8_0",
    # JSON Formatter
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\bcjindcccaagfpapjjmafapmmgkkhgoa\0.10.2_0",
    # Kami for Google Chrome
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ecnphlgnajanjnkcmbpancdjoidceilk\2.0.25028_0",
    # Keepa - Amazon Price Tracker
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\neebplgakaahbhdphmkckjjcegoiijjo\5.64_0",
    # Keeper Password Manager & Digital Vault
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\bfogiafebfohielmmehodmfbbebbbpei\18.0.0_0",
    # Keywords Everywhere - Keyword Tool
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hbapdpeemoojbophdfndmlgdhppljgmp\11.53_0",
    # LastPass: Free Password Manager
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hdokiejnpimakedhajhdlcegeplioahd\4.155.0_0",
    # Loom – Screen Recorder & Screen Capture
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\liecbddmkiiihnedobmlmillhodjkdmb\5.5.206_0",
    # Mailtrack – Email Tracker for Gmail
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ndnaehgpjlnokgebbaldlmgkapkpjkkb\12.91.0_0",
    # Maple
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ldlofabknfheicdhcoceihimnccpfamj\1.0.2_0",
    # McAfee Anti-tracker
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hkflippjghmgogabcfmijhamoimhapkh\1.0.0.1356_0",
    # Media Downloader for Instagram
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\cbnmngfnpibbjobleaghjkdlibjhphlf\1.0.3_0",
    # MetaMask
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\nkbihfbeogaeaoehlefnkodbefgpgknn\13.44.0_0",
    # Momentum
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\laookkfknpbbblfpciffpaejjkokdgca\2.27.4_0",
    # MozBar
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\eakacpaijcpapndcfffdgphdiccmpknp\5.0.16_0",
    # Nimbus Extension
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\objfmikcifoabcepfanenmngecemkmng\2.0_0",
    # Norton Password Manager
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\admmjipmmciaobhojoghlmleefbicajg\8.3.1.1495_0",
    # Notion Web Clipper
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\knheggckgoiihginacbkhaalnibhilkk\0.2.13_0",
    # OneTab
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\chphlpgkkbolifaimnlloiipkdnihall\2.18_0",
    # Page Ruler
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\jcbmcnpepaddcedmjdcmhbekjhbfnlff\0.1.8_0",
    # PDF Merger
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\nimljidihnlgjnanpiaaaakfmnfocnih\1.0.3_0",
    # Pixel Perfect Extension
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\clnipilleohelandpaijhefjmafmhfje\0.1.2_0",
    # Postman Interceptor
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\aicmkgpgakddgnaphhhpliifpcfhicfo\3.2.1_0",
    # Privacy Badger
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pkehgijcmpdhfbdbbnkijodmdjhbjlgp\2026.8.7_0",
    # ProWritingAid: Grammar Checker & Paraphrasing Tool
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\npnbdojkgkbcdfdjlfdmplppdphlhhcf\2.8.48222_0",
    # Quick Pocket
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\gccdebcpenpmmnaedfmkdhpbnihcdedh\1.8.3_0",
    # React Developer Tools
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\fmkadmapgofadopljbjfkapdkoienihi\7.0.1_0",
    # Read Aloud: A Text to Speech Voice Reader
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hdhinadidafjejdhmfkjgnolgimiaplp\2.24.0_0",
    # Reverso – Translation, dictionary
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\onhiacboedfinnofagfgoaanfedhmfab\3.12.396_0",
    # Reward Transparency & Optimizer
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\cadjjheggoeonnkjppbapoapobhbhiam\0.1.1_0",
    # RightInbox: Email Reminders, Tracking, Notes
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\mflnemhkomgploogccdmcloekbloobgb\11.0.2_0",
    # RoboForm Password Manager
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pnlccmojcmeohlpggmfnbbiapkmbliob\10.0.0.0_0",
    # SafeToOpen Browser Security and Privacy
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ekfkopmgnijagfmjgcjkbffcnmggekec\8.1.0_0",
    # Save Emails to Drive by cloudHQ
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\glgaegbgegomicnedooifcbnmppmofkf\1.0.2.23_0",
    # Savewise: Stack Cashback Shopping Portals
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\mmdidpkgkknffjbnnbpcdpchhbmdmbga\1.12.3_0",
    # SEOquake: On-Page SEO Checker
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\akdgnmcogleenhbclghghlkkdndkjdjc\4.0.0_0",
    # Session Buddy - Tab & Bookmark Manager
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\edacconmaakjimmfgnblocblbcdcpbko\4.1.2_0",
    # SetupVPN - Lifetime Free VPN
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\oofgbpoabipfcfjapgnbbjjaenockbdp\4.0.9_0",
    # Similarweb - Website Traffic, AI Traffic & SEO Checker
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hoklmmgfnpapgjgcpechhaamimifchmp\6.12.22_0",
    # Simplify Gmail
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pbmlfaiicoikhdbjagjbglnbfcbcojpj\3.4.9_0",
    # SocialPilot
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\cabldpgmkejdhjbgmeooocablkljdbcg\1.6.2_0",
    # Speed Dial 2 New tab
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\jpfpebmajhhopeonhlcgidhclcccjcik\4.0.0_0",
    # SponsorBlock for YouTube - Skip Sponsorships
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\mnjggcdmjocbbbhaepdhchncahnbgone\6.1.6_0",
    # Spotify Web Player Hotkeys
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pdcbjjmgfakcbbchppeemlfpfgkdmjji\1.4.3_0",
    # Streak CRM for Gmail
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pnnfemgpilpdaojpnkjdgfgbnnjojfik\7.97_0",
    # Super Simple Highlighter
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hhlhjgianpocpoppaiihmlpgcoehlhio\2026.06.29_0",
    # Tab Manager by Workona
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ailcmbgekjpnablpdkmaaccecekgdhlh\3.1.33_0",
    # Tab Wrangler
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\egnjhciaieeiiohknchakcodbpgjnchh\8.4.0_0",
    # Todoist for Chrome: Planner & Calendar
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\jldhpllghnbhlbpcmnajkpdmadaolakh\12.21.9_0",
    # Toggle JavaScript
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\cidlcjdalomndpeagkjpnefhljffbnlo\2.0_0",
    # Touch VPN
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\oiboifjlhhjpikbjfjcgmhlfjnffnpmn\2.7.7_0",
    # uBlacklist
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\pncfbmialoiaghdehhbnbhkkgmjanfhe\10.0.3_0",
    # uBlock Origin Lite
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ddkjiahejlhfcafbddmgiahcphecmpfh\2026.825.1619_0",
    # URL Cleaner
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\dffbjiomnajbmlhjelpipfldgkijdemn\0.1.0_0",
    # User-Agent Switcher for Chrome
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\djflhoibgkdhkhhcedjiklpkjnoahfmg\2.0.2_0",
    # Video Speed Controller
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\nffaoalbilbmmfgbnbgppjihopabppdk\0.11.1_0",
    # Waltrack | Walmart Price Tracker
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hhafpmbhnjfnlmlmafmbmnpfliohjkkl\6.9.1_0",
    # Weather extension
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\mfhfabihcpklaoadegkbfpfbenneniad\4.2_0",
    # WebCopilot.ai - Use GPT on any input box
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\dpbbbjcogocehfjmeggcfncdmijbaimg\2.2.0_0",
    # What font - font finder
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\opogloaldjiplhogobhmghlgnlciebin\1.0.4_0",
    # Window Resizer
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\hgjfanlllikpfpaadggdbchdpcbiaeei\0.1.9_0",
    # Wordtune: AI Paraphrasing and Grammar Tool
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\nllcnknpjnininklegdoijpljgdjkijc\9.20.0_0",
    # youBlock - uBlock Alternative
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\User Data\Default\Extensions\ldadnegmmggmmgbijlnmjhcnjcpgkfdj\1.0.3_0",
    # YouTube NonStop
    r"C:\Users\Kavindu\AppData\Local\Google\Chrome\Userf:f Data\Default\Extensions\nlkaejimjacpillmajjnopmpbkbnocid\0.9.2_0",
]

def analyze_one(ext_path):
    manifest = load_manifest(ext_path)
    code = collect_js_source(ext_path)
    declared, used, unused, high_risk_found = analyze_permissions(manifest, code)
    category_counts, category_matches = categorize_permissions(declared)
    host_perms = manifest.get("host_permissions", [])
    site_results = check_sensitive_sites(host_perms)
    features = build_features(declared, unused, high_risk_found, category_counts, site_results)

    name = manifest.get("name", "Unknown")
    print(f"{name}  |  unused={unused}  |  high_risk={high_risk_found}")
    return name, features


def main():
    rows = []
    for ext_path in EXTENSIONS_TO_ANALYZE:
        try:
            name, features = analyze_one(ext_path)
            rows.append([name, ext_path] + features + ["LOW"])  # default label, edit after
        except Exception as e:
            print(f"!! Skipped {ext_path}: {e}")

    with open("dataset.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "folder_path"] + FEATURE_NAMES + ["label"])
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} rows to dataset.csv")
    print("Now open dataset.csv and fix the 'label' column for each row!")


if __name__ == "__main__":
    main()