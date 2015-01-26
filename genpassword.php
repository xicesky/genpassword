#!/usr/bin/php
<?php

    $version = '1.1';

    $charsets = array(
        'Left1' => "1234qwerasdfxcv",
        'Right1' => "7890uiopjklm",
        'Mid' => "56tghbn",
        'BadIntl' => "yzäöüß",
        'RSymb' => "+-.,",
        'Number' => "0123456789",
    
        'Left' => "1234qwerasdfxcvtgbQWERASDFXCVTGB",
        'Right' => "7890uiopjklmhnUIOPJKLMHN,.-*#_:;",

        'L2' => "1234qwerasdfyxcv",
        'R2' => "7890uiophjklnm.-",
        'Simple' => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        'Compat1' => "qwerasdfyxcv",
        'Compat2' => "uiohjklnm",
        );

    //$pattern = array( 'Left', 'Right', );
    //$pattern = array( 'L2', 'R2' );
    $pattern = array( 'Simple' );
    //$pattern = array( 'Compat1', 'Compat2' );

    function entropy($s) {
        return strlen(count_chars($s, 3));
    }

    function secrand_8bit() {
        return ord(mcrypt_create_iv(1));
    }

    function secrand_select($s) {
        $n = strlen($s);
        $i = secrand_8bit() % $n; // FIXME: This is not fair for non-power 2 strlen.
        return substr($s, $i, 1);
    }

    function print_sets($charsets) {
        $fmt = "%8s %4s %s\n";
        $s = "";
        $s .= sprintf($fmt, "Name", "Entropy", "Characters in set");
        foreach ($charsets as $k => $v) {
            $s .= sprintf($fmt, $k, entropy($v), $v);
        }
        return $s;
    }

    function accumulate_pattern($pattern, $len, $init, $f_accu) {
        $n = count($pattern);
        $x = $init;
        for ($i = 0; $i < $len; $i++) {
            $p = $pattern[ $i % $n ];
            $x = $f_accu($x, $p);
        }
        return $x;
    }

    function calc_entropy($pattern, $charsets, $pwlength) {
        $f = function($entropy, $p) use ($charsets) {
            $e = entropy($charsets[$p]);
            $entropy = gmp_mul($entropy, $e);
            $s = gmp_strval($entropy, 2);
            $xp = strlen($s)-1; // PHP's GMP binding is stupidly incomplete
            //printf("%8s %4s  ~exp: %4d\n", $p, $e, $xp);
            return $entropy;
        };
        return accumulate_pattern($pattern, $pwlength, 1, $f);
    }

    function gen_password($pattern, $charsets, $pwlength, $callback = false) {
        $f = function($pw, $p) use ($charsets, $callback) {
            if ($callback !== false) $callback($pw, $p);
            return $pw . secrand_select($charsets[$p]);
        };
        return accumulate_pattern($pattern, $pwlength, "", $f);
    }

    function entropy_info($entropy) {
        // First, lets get the base 2 exponent, this will be much simpler
        $xp = $exponent = strlen(gmp_strval($entropy, 2)) - 1; // No better way atm.
        // Assume a massive cracking scenario:
        $exps = array(
            array(40, "seconds"),   // 2^40 (~ guesses/sec) -- TODO: Update this in the future or use an estimate f(t)
            array(12, "hours"),     // 2^12 (~ secs/hour)
            array( 5, "days"),      // 2^5  (~ hours/day)
            array( 9, "years"),     // 2^9  (~ days/year)
            array(20, "million years"), // 2^20 ~ 1 million
            array(10, "billion years"), // 2^10 ~ 1000
            array(10, "trillion years"),
        );
        $s = "less than a second";
        for ($i = 0; $i < count($exps); $i++) {
            $e = $exps[$i];
            $xp -= $e[0];
            if ($xp < 0) break;
            $s = $e[1];
        }
        return "An entropy of 2^$exponent means your password can probably be cracked in $s";
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Let's fetz sagte der Frosch und sprang in den Mixer.
    //

    // Check for extensions and PEAR packages

    if (!extension_loaded("gmp")) {
        printf("\nThis script requires the php extension \"gmp\" to be installed, sorry.\n");
        exit(1);
    }

    require_once 'PEAR/Info.php';
    if (!PEAR_Info::packageInstalled('Console_CommandLine', '1.0')) {
        printf("\nThis script requires the PEAR package \"Console_CommandLine\" to be installed, sorry.\n");
    }

    // Command line (option) handling
    require_once 'Console/CommandLine.php';
    $parser = new Console_CommandLine();
    $parser->description = '(Relatively) secure password generator';
    $parser->version = $version;
    $parser->addOption("length", array(
        'short_name'    => '-l',
        'long_name'     => '--length',
        'description'   => 'number of password characters to generate',
        'action'        => 'StoreInt',
        'default'       => 16,
        ));
    /* $parser->addOption('verbose', array(
        'short_name'    => '-v',
        'long_name'     => '--verbose',
        'description'   => 'turn on verbose output',
        'action'        => 'StoreTrue',
        'default'       => true,
    ));
     */

    $parser->addOption('verbosity', array(
        'short_name'    => '-v',
        'long_name'     => '--verbose',
        'description'   => 'Increase verbosity',
        'action'        => 'Counter',
        'default'       => 1,
    ));

    $parser->addOption('quiet', array(
        'short_name'    => '-q',
        'long_name'     => '--quiet',
        'description'   => 'Turn off output (except the generated password ofc)',
        'action'        => 'StoreTrue',
    ));

    try {
        $result = $parser->parse();
        $options = $result->options;
        if ($options['quiet']) $options['verbosity'] = 0;
        //print_r($options);
    } catch (Exception $exc) {
        $parser->displayError($exc->getMessage());
        die();
    }

    $vv = $options['verbosity'];

    ($vv >= 1) && printf("------------------------------------------------------------------------------\n");
    ($vv >= 1) && printf("(Relatively) secure password generator (v$version) [written by sky@q1cc.net]\n");
    ($vv >= 2) && printf("Charsets:\n");
    ($vv >= 2) && printf("%s", print_sets($charsets));
    ($vv >= 1) && printf("------------------------------------------------------------------------------\n");

    ($vv >= 1) && printf("Pattern: " . implode(' ', $pattern) . "\n");
    ($vv >= 1) && printf("Desired passworld length: " . $options['length'] . "\n");
    ($vv >= 1) && $entropy = calc_entropy($pattern, $charsets, $options['length']);
    ($vv >= 1) && printf("Entropy check: " . entropy_info($entropy) . "\n");

    ($vv >= 1) && printf("Generating password: ");
    $pw = gen_password($pattern, $charsets, $options['length'], ($vv >= 1) ? (function($pw, $p) { printf("."); }) : false);
    ($vv >= 1) && printf("\n");

    ($vv >= 1) && printf("Here is your new password: ");
    printf("%s\n", $pw);

?>
