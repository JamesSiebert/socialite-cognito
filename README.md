# Socialite / AWS Cognito User Pools

```bash
composer require socialiteproviders/cognito
```

###Project Notes:
This allows socialite to connect to AWS Cognito and use the user pool for auth.\
This is based on Based on: [Laravel Passport Provider](https://github.com/SocialiteProviders/Laravel-Passport) \
This project relies on [Manager](https://github.com/socialiteproviders/manager)

## Tutorial: How to create a starter project
This install is based on a fresh project (Laravel Framework v8.61.0)

#### Create and link up database in .env

#### Add environmental variables
Path: `.env`
```php
SERVER_PORT=8001 # Not required, will serve on a different port, good for running multiple apps
COGNITO_HOST=https://your_cognito_domain.auth.your_region.amazoncognito.com
COGNITO_CLIENT_ID=abc123
COGNITO_CLIENT_SECRET=aaabbbccc111222333
COGNITO_REDIRECT_URI=https://your-app.au.ngrok.io/oauth2/callback
COGNITO_SIGN_OUT_URL=https://logout-redirect-to-site.com
COGNITO_LOGIN_SCOPE="aws.cognito.signin.user.admin+openid+profile"
```

#### Modify AppServiceProvider
Path: `app/Providers/AppServiceProvider.php`
```php
use Illuminate\Support\Facades\Schema;
public function boot()
{
Schema::defaultStringLength(125);
}
````

#### Dependencies
For simplicity we will use standard laravel auth and bootstrap.
```php
composer require laravel/ui
composer require laravel/socialite
composer require socialiteproviders/cognito
```

#### Event Listener
Path : `app/Providers/EventServiceProvider` \
Add this to array
```php
protected $listen = [
    Registered::class => [
        SendEmailVerificationNotification::class,
    ],
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // add your listeners (aka providers) here
        'SocialiteProviders\\Cognito\\CognitoExtendSocialite@handle',
    ],
];
```

#### Add configuration
Path: `config/services.php`
```php
'cognito' => [
   'host' => env('COGNITO_HOST'),
   'client_id' => env('COGNITO_CLIENT_ID'),
   'client_secret' => env('COGNITO_CLIENT_SECRET'),
   'redirect' => env('COGNITO_REDIRECT_URI'),
],
```

#### Install Auth UI
`php artisan ui bootstrap --auth`

#### Edit Login View
Path: `resources/views/auth/login.blade.php`
Comment out the existing form and add this:
```php
<div class="form-group row mb-0 mt-3">
    <div class="col-md-8 offset-md-4">
        <a href="{{ url('/oauth2/login') }}" class="btn btn-warning">Cognito Login</a>
    </div>
</div>
```


####Add logout buttons
Path: `resources/views/home.blade.php`
```php
<h2>Home - User Dashboard</h2>
<div class="form-group row mb-0 mt-3">
    <div class="col-md-8 offset-md-4">
        <a href="{{ url('/oauth2/logout') }}" class="btn btn-warning">Cognito Logout</a>
    </div>
</div>
<div class="form-group row mb-0 mt-3">
    <div class="col-md-8 offset-md-4">
        <a href="{{ url('/oauth2/switch-account') }}" class="btn btn-warning">Switch Account</a>
    </div>
</div>
```


### Add cognito configuration
Path: `config/services.php`

```php
'laravelpassport' => [    
  'client_id' => env('LARAVELPASSPORT_CLIENT_ID'),  
  'client_secret' => env('LARAVELPASSPORT_CLIENT_SECRET'),  
  'redirect' => env('LARAVELPASSPORT_REDIRECT_URI') 
],
```

#### Modify NavBar Links
Path: `resources/views/layouts/app.blade.php` \
*comment out existing right 'ul' section and replace with:
```php
<!-- Right Side Of Navbar -->
<ul class="navbar-nav ml-auto">
    @guest
        <li class="nav-item">
            <a href="{{ url('/oauth2/login') }}" class="nav-link">Cognito Login / Register</a>
        </li>
    @else
        <li class="nav-item dropdown">
            <a id="navbarDropdown" class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" v-pre>
                {{ Auth::user()->first_name }}
            </a>

            <div class="dropdown-menu dropdown-menu-right" aria-labelledby="navbarDropdown">
                <a href="{{ url('/oauth2/logout') }}" class="dropdown-item">Cognito Logout</a>
                <a href="{{ url('/oauth2/switch-account') }}" class="dropdown-item">Switch Account</a>
            </div>
        </li>
    @endguest
</ul>
```

### Modify welcome view links
Path: `resources/views/welcome.blade.php`
```php
@auth
    <a href="{{ url('/home') }}" class="text-sm text-gray-700 dark:text-gray-500 underline">Dashboard</a>
@else
    <a href="{{ url('/oauth2/login') }}" class="text-sm text-gray-700 dark:text-gray-500 underline">Login</a>
@endauth
```

#### Modify default user model
Path: `app/Models/User.php`
```php
protected $fillable = [
   'first_name',
   'last_name',
   'email',
   'password',
   'provider',
   'provider_id',
];
```

#### Modify User Migration
Path: `database/migrations/..._create_users_table.php`
```php
Schema::create('users', function (Blueprint $table) {
   $table->id();
   $table->string('first_name');
   $table->string('last_name');
   $table->string('email');
   $table->timestamp('email_verified_at')->nullable();
   $table->string('password')->nullable();
   $table->string('provider');
   $table->string('provider_id');
   $table->rememberToken();
   $table->timestamps();
});
```

#### Run migration
`php artisan migrate`

#### Compile assets
`npm install && npm run dev`

#### Add Auth Routes
Path: `routes/web.php`
```php
Route::get('/', function () { return view('welcome'); })->name('welcome');

Auth::routes();

Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');

// OAuth (Cognito)
Route::get('oauth2/login', [App\Http\Controllers\Auth\LoginController::class, 'redirectToExternalAuthServer']);                                       // Login button - Post to OAuth Server
Route::get('oauth2/callback', [App\Http\Controllers\Auth\LoginController::class, 'handleExternalAuthCallback']);                                      // For OAuth2 Callback (Cognito)
Route::get('oauth2/logout', [App\Http\Controllers\Auth\LoginController::class, 'cognitoLogout'])->name('oauth-logout');                         // OAuth2 triggered logout (Cognito)
Route::get('oauth2/switch-account', [App\Http\Controllers\Auth\LoginController::class, 'cognitoSwitchAccount'])->name('oauth-switch-account');   // Logout and login to another account
```

#### Login Controller
Path: `app/Http/Controllers/Auth/LoginController.php`
```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

class LoginController extends Controller
{
    use AuthenticatesUsers;

    // Where to redirect users after login.
    protected $redirectTo = RouteServiceProvider::HOME;

    public function __construct()
    {
        // guest only except logout functions
        $this->middleware('guest')->except('logout', 'cognitoLogout', 'cognitoSwitchAccount');
    }

    // POST to Cognito Host
    // Example COGNITO_HOST/login?client_id=CLIENT_ID&response_type=code&scope=aws.cognito.signin.user.admin+email+openid+phone+profile&redirect_uri=REDIRECT_URI
    public function redirectToExternalAuthServer(): \Symfony\Component\HttpFoundation\RedirectResponse
    {
        return Socialite::driver('cognito')->redirect();
    }

    // Callback from AWS Cognito
    // Example: http://myapp.ngrok.io/cognito/callback?code=1234&state=abc
    public function handleExternalAuthCallback(): RedirectResponse
    {
        $user = Socialite::driver('cognito')->stateless()->user(); // NOTE STATELESS - https://stackoverflow.com/questions/30660847/laravel-socialite-invalidstateexception
        //dd($user); // Show the available user attributes
        $authUser = $this->findOrCreateUser($user, 'cognito');
        Auth::login($authUser, true);

        return redirect()->route('home');
    }

    // If a user has registered before using social auth, return the user else, create a new user
    public function findOrCreateUser($user, $provider): User
    {
        // Search DB for a user with the provider_id = cognito user sub
        $authUser = User::where('provider_id', $user->user['sub'])->first();
        if ($authUser) {
            // User found
            return $authUser;
        }

        // Access user profile data in cognito user
        $passportUser = $user->user;

        /* EXAMPLE COGNITO USER PROFILE
        "sub" => "88889999-2222-0000-1111-222111110000" // Subject - Cognito UUID of the authenticated user
        "birthdate" => "some_string"
        "email_verified" => "true"
        "gender" => "some gender string"
        "phone_number_verified" => "false"
        "phone_number" => "+61402172740"
        "given_name" => "FirstName"
        "family_name" => "LastName"
        "email" => "example@example.com"
        "username" => "88889999-2222-0000-1111-222111110000"
        */

        // Create new local user
        return User::create([
            'first_name'     => $passportUser['given_name'],
            'last_name'     => $passportUser['family_name'],
            'email'    => $passportUser['email'],
            'provider' => $provider,
            'provider_id' => $passportUser['sub']
        ]);
    }

    // Logout of cognito, logout of app, redirect to specified logout url
    // Notes: Must be SSL, cognito and env sign out url must match. Ngrok has issues here so I use an external url instead.
    public function cognitoLogout(){
        $AUTH_DOMAIN = env('COGNITO_HOST');
        $CLIENT_ID = env('COGNITO_CLIENT_ID');
        $LOGOUT_URI = env('COGNITO_SIGN_OUT_URL'); // hangs when redirecting to ngrok

        $cognitoLogoutURL="$AUTH_DOMAIN/logout?client_id=$CLIENT_ID&logout_uri=$LOGOUT_URI";

        // Log out app
        Auth::logout();

        // Call cognito logout endpoint
        return Redirect($cognitoLogoutURL);
    }

    // Logout of cognito, logout of app, redirect to cognito login.
    // Notes: Must be SSL, cognito and env redirect url must match. Use Ngrok for dev SSL simulation.
    public function cognitoSwitchAccount(){
        $AUTH_DOMAIN = env('COGNITO_HOST');
        $CLIENT_ID = env('COGNITO_CLIENT_ID');
        $REDIRECT_URI = env('COGNITO_REDIRECT_URI');
        $SCOPE = env('COGNITO_LOGIN_SCOPE');

        $cognitoLogoutURL="$AUTH_DOMAIN/logout?client_id=$CLIENT_ID&response_type=code&scope=$SCOPE&redirect_uri=$REDIRECT_URI";

        // Log out app
        Auth::logout();

        // Call cognito logout endpoint
        return Redirect($cognitoLogoutURL);
    }
}
```

#### Update environmental variables
Path: `.env`
```php
COGNITO_HOST - Cognito hosted login ui address - get this from cognito user pools > App integration > domain name
COGNITO_CLIENT_ID= Cognito user pool app client > App client id
COGNITO_CLIENT_SECRET= Cognito user pool > app client > App client secret
COGNITO_REDIRECT_URI=https://your-app.au.ngrok.io/oauth2/callback - Https - Must set in cognito client app (Callback URL)
COGNITO_SIGN_OUT_URL= Https site for logout redirection. There are issues with using a ngrok url so I use an external url for testing. Must also set in cognito (Sign out URL)
COGNITO_LOGIN_SCOPE="aws.cognito.signin.user.admin+openid+profile" requested data from cognito
```

#### Local testing
Cognito only works when using SSL so to work around this you can use [ngrok (free)](https://ngrok.com/)
On Windows I just place in in my C:\

```php
php artisan serve
cd c:\
ngrok http localhost:8001
```

If you want to not have to update the url each time you refresh, it is $5/mth. \
`ngrok http --region=au --hostname=your-app-name.au.ngrok.io 8001`

### Useful info

#### Cognito endpoints:
```php
'authorize_uri' - 'oauth2/authorize'
'token_uri'     - 'oauth2/token'
'userinfo_uri'  - 'oauth2/userInfo'

//Logout and expire sso cookies everywhere
$AUTH_DOMAIN/logout?client_id=$CLIENT_ID&logout_uri=$LOGOUT_URI";
$AUTH_DOMAIN/logout?client_id=$CLIENT_ID&response_type=code&scope=$SCOPE&redirect_uri=$REDIRECT_URI";
```

### More info on cognito user pool settings coming soon...
