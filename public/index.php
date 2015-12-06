<?php
include dirname(__DIR__).'/vendor/autoload.php';

function makeAPIRequest($token) 
{
    $url = sprintf("%s/api/session?client_id=%s&token=%s", $_ENV['SIIL_URL'], $_ENV['SIIL_SITE_ID'], $token);
    $sigStr = sprintf("%s\t%s", $_ENV['SIIL_SITE_ID'], $token);
    $sig = base64_encode(hash_hmac('sha512', $sigStr, $_ENV['SIIL_SITE_PRIVATE'], true));
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["X-Authorization: $sig"]);

    if ($_ENV['VALIDATE_CERT'] === "false") {
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    }
    $resp = curl_exec($ch);
    if (curl_getinfo($ch, CURLINFO_HTTP_CODE) == 200) {
        curl_close($ch);
        return json_decode($resp, true);
    } else {
        curl_close($ch);
        return null;
    }
}

function verify($tokenInfo) 
{
    $verification = $tokenInfo['verification'];
    unset($tokenInfo['verification']);
    return $verification == base64_encode(hash_hmac('sha512', json_encode($tokenInfo, JSON_UNESCAPED_UNICODE), $_ENV['SIIL_SITE_PRIVATE'], true));
}

function handleSuccessAction() 
{
    if ($_SERVER['REQUEST_METHOD'] != 'POST') {
        echo "No can do chief! I only accept post method";
    } else {
        if (isset($_POST['token'])) {
            $tokenInfo = makeAPIRequest($_POST['token']);
            if (isset($_GET['siil_action']) && $_GET['siil_action'] == 'signout') {
                //Signout handler
                setcookie("token", "", time() - 3600);
                header("Location: index.php");
            } else {
                if (!is_null($tokenInfo)) {
                    if ($tokenInfo["site_id"] == $_ENV['SIIL_SITE_ID']) {
                        if (verify($tokenInfo)) {
                            setcookie("token", $tokenInfo["token"], 0);
                            header("Location: index.php");
                        } else {
                            echo 'Bad token!';
                        }
                    }
                }
            }
        } else {
            setcookie("token", "", time() - 3600);
            echo 'No token!';
        }
    }
}

function handleCancelAction($hb) 
{
    $params = [
        'siil_url' => $_ENV['SIIL_URL'], 
        'site_id' => $_ENV['SIIL_SITE_ID']
    ];
    echo $hb->render("cancel", $params);
}

function handleDefault($hb)
{
    $token = isset($_COOKIE['token']) ? $_COOKIE['token'] : null;
    $params = [
        'siil_url' => $_ENV['SIIL_URL'], 
        'site_id' => $_ENV['SIIL_SITE_ID'],
        'authed' => false
    ];

    if (!is_null($token)) {
        $tokenInfo = makeAPIRequest($token);
        if (!is_null($tokenInfo) && verify($tokenInfo)) {
            $params['authed'] = true;
            $params['first_name'] = $tokenInfo['user']['first_name'];
            $params['last_name'] = $tokenInfo['user']['last_name'];
            $dt = DateTime::createFromFormat(DateTime::RFC3339, $tokenInfo['expires_at']);
            $now = new DateTime("now");
            $params['expiry'] = $dt->diff($now)->format("%h hour(s) %I minutes %S seconds");
            $params['token'] = $tokenInfo['token'];
            $params['code'] = $tokenInfo['user']['code'];
        } else {
            setcookie("token", "", time() - 3600);
        }
    }

    echo $hb->render('index', $params);
}

//Load environment configuration
$dotenv = new Dotenv\Dotenv(dirname(__DIR__));
$dotenv->load();

//Handlebars template renderer
$hb = new Handlebars\Handlebars(array(
    'loader' => new \Handlebars\Loader\FilesystemLoader(dirname(__DIR__).'/tmpl/'),
    'partials_loader' => new \Handlebars\Loader\FilesystemLoader(
        dirname(__DIR__) . '/tmpl/',
        array(
            'prefix' => '_'
        )
    )
));

$action = isset($_GET['action']) ? $_GET['action'] : null;

//"router"
switch($action) {
    case 'success':
        handleSuccessAction();
    break;
    case 'cancel':
        handleCancelAction($hb);
    break;
    default:
        handleDefault($hb);
    break;
}