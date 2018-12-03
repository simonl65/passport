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
# Front-end
## Add Contacts table and seed data
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
## CRUD
1. Register `/contact` as an API route in `api.php`:
    ```php
    Route::apiResource('contact', 'Api\ContactController');
    ```
1. Add to `ContactController.php`:
    ```php
    namespace App\Http\Controllers\Api;

    use App\Http\Controllers\Controller;
    use App\Contact;
    use App\Http\Resources\Contact as ContactResource;
    use Illuminate\Http\Request;
    :
    public function index()
    {
        // Only return contact(s) related to this user:
        $contacts = request()->user()->contacts;
        return ContactResource::collection($contacts);
    }
    ```
1. `pa make:resource Contact`
1. Change the 'toArray()' function in `Contact.php` to:
    ```php
    public function toArray($request)
    {
        return [
            'id'       => $this->id,
            'fullName' => $this->name,
            'tel'      => $this->phone,
            'created'  => (string)$this->created_at->format('Y-m-d'),
        ];
    }
    ```
    This allows us to define what gets returned, what labels to use and to format the data.
1. To enable `/contact/{id}`
    ```php
    public function show(Contact $contact)
    {
        return new ContactResource($contact);
    }
    ```

### Enable **store**
1. Update `Contact` _model_:
    ```php
    protected $fillable=[ 'name', 'phone' ];

    // Relationship with User model:
    public function user() {
        return $this->belongsTo(User::class);
    }
    ```
1. Add reciprocal relationship in `User` _model_:
    ```php
    /**
     * User-Contact relationship:
     */
    public function contacts()
    {
        return $this->hasMany(Contact::class);
    }
    ```
1. Update the `store` function in `ContactController`:
    ```php
    // User is expected to be authenticated, so User model should be
    // available here:
    $contact = $request
            ->user()
            ->contacts()
            ->create( $request->all() );
    return new ContactResource($contact);
    ```
### Now protect the routes:
1. In `ContactController`:
    ```php
    class ContactController extends Controller
    {
        /**
        * Protect with middleware:
        */
        public function __construct()
        {
            return $this->middleware('auth:api');
        }
        ...
    ```
1. Define the `update` function:
    ```php
    public function update(Request $request, Contact $contact)
    {
        // Only allow updates on user's own resource:
        if( $request->user()->id !== $contact->user_id ) {
            return response()->json(['error' => 'Unauthorised action'], 401);
        }

        $contact->update( $request->all() );
        return new ContactResource($contact);
    }
    ```
1. Define the `destroy` function:
    ```php
    public function destroy(Contact $contact)
    {
        // Only allow updates on user's own resource:
        if( request()->user()->id !== $contact->user_id ) {
            return response()->json(['error' => 'Unauthorised action'], 401);
        }

        $contact = $contact->delete();

        return response()->json(null, 200);
    }
    ```
### ^^^^^^^^^^CRUD Completed^^^^^^^^^^
1. 
