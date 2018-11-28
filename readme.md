# API Auth using Laravel & Passport
See: https://laravel.com/docs/5.6/passport
## Passport Set-up
1. Create a Laravel 5.6 project:  
    ```bash
    composer create-project --prefer-dist passport 5.6
    ```
1. `cd passport`
1. Set-up .env (don't forget mysql=localhost)
1. `pa make:auth`
1. `composer require laravel/passport`
1. `pa migrate`
1. `pa passport:install`
1. Add the following to `App\User.php`
    ```php
    use Laravel\Passport\HasApiTokens;
    :
    class User extends Authenticatable
    {
        use HasApiTokens, Notifiable;
        ...
    ```
1. Update `AuthServiceProvider.php`:
    ```php
    use Laravel\Passport\Passport;
    :
        public function boot()
        {
            $this->registerPolicies();

            Passport::routes();
        }
    ```
1. Update `config/auth.php`:
    ```php
    'api' => [
                'driver' => 'passport',
                'provider' => 'users',
            ],
    ```

## Access an API Route
1. Open REST Client (e.g. Insomnia or Postman)
1. Create new oAuth request:
    ```
    POST http://passport/oauth/token
    HEADER:
        Content-Type: application/x-www-form-urlencoded
        Accept: application/json
    BODY:
        grant_type: password
        client_id: <id from oauth_clients table>
        client_secret: <"Passport Password Grant Client" from oauth_clients table>
        username: <api@nowhere.test>
        password: <password>
        scope:
    ```
1. Run that call to get the access_token
1. Create new request:
    ```
    GET http://passport/api/user
    HEADERS:
        Accept: application/json
        Authorization: Bearer <access_token>
    ```
1. Making that request should result in a user details response

## Routes for Register & Login
1. `pa make:controller Api\\AuthController`
1. Add the following to `AuthController`:
    ```php
    use App\User;
    use GuzzleHttp\Client;
    use Illuminate\Support\Facades\Hash;
    :
        /**
     * /register
     */
    public function register(Request $request)
    {
        // Validate user data:
        $request->validate([
            'email'    => 'required|email',
            'name'     => 'required',
            'password' => 'required'
        ]);

        // Enter user details into database:
        $user           = User::firstOrNew(['email' => $request->email]);
        $user->name     = $request->name;
        $user->email    = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        $http = new Client;

        $response = $http->post(url('oauth/token'), [
            'form_params' => [
                'grant_type'    => 'password',
                'client_id'     => '2',
                'client_secret' => 'AeHzbD9lkl2lJO1zSdHLGxkS44xrM0qmi4BVI7Gp',
                'username'      => $request->email,
                'password'      => $request->password,
                'scope'         => ''
            ]
        ]);

        return response(['data' => json_decode((string)$response->getBody(), true)]);
    }

    /**
     * /login
     */
    public function login(Request $request)
    {
        $request->validate([
            'email'    => 'required',
            'password' => 'required'
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response([
                'status'  => 'error',
                'message' => 'User not found.'
            ]);
        }

        if (Hash::check($request->password, $user->password)) {
            $http = new Client;

            $response = $http->post(url('oauth/token'), [
                'form_params' => [
                    'grant_type'    => 'password',
                    'client_id'     => '2',
                    'client_secret' => 'AeHzbD9lkl2lJO1zSdHLGxkS44xrM0qmi4BVI7Gp',
                    'username'      => $request->email,
                    'password'      => $request->password,
                    'scope'         => ''
                ]
            ]);

            return response(['data' => json_decode((string)$response->getBody(), true)]);
        }
    }
    ```
1. Add the `/register` & `/login` routes to `api.php`:
    ```php
    Route::post('/register', 'Api\AuthController@register');
    Route::post('/login',    'Api\AuthController@login');
    ```
## Add a front-end (Contacts)
1. Initialisations:
    ```bash
    pa make:model Contact -a
    pa make:seed UsersTableSeeder
    pa make:seed ContactsTableSeeder
    ```
1. Set the contacts table migration:
    ```php
    $table->unsignedInteger('user_id');
    $table->string('name');
    $table->string('phone');
    $table->timestamp('created_at')->default(DB::raw('CURRENT_TIMESTAMP'));
    $table->timestamp('updated_at')->default(DB::raw('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'));
    ```
1. Update `ContactFactory.php`:
    ```php
    return [
        'name' => $faker->name,
        'phone' => $faker->phoneNumber,
        'user_id' => App\User::all()->unique()->random()->id
    ];
    ```
1. Update `UsersTableSeeder.php`:
    ```php
    use App\User;
    :
    return factory(User::class, 20)->create();
    ```
1. Update `ContactsTableSeeder.php`:
    ```php
    use App\Contact;
    :
    return factory(Contact::class, 20)->create();
    ```
1. Update `DatabaseSeeder.php`:
    ```php
    $this->call(UsersTableSeeder::class);
    $this->call(ContactsTableSeeder::class);
    ```
1. On the **_VM_**, run:
    ```bash
    pa migrate --seed
    ```
1. 
