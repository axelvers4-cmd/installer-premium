#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Services/Servers/ServerDeletionService.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Delete Server..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Facades\Auth;
use Pterodactyl\Exceptions\DisplayException;
use Illuminate\Http\Response;
use Pterodactyl\Models\Server;
use Illuminate\Support\Facades\Log;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Services\Databases\DatabaseManagementService;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class ServerDeletionService
{
    protected bool $force = false;

    /**
     * ServerDeletionService constructor.
     */
    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $daemonServerRepository,
        private DatabaseManagementService $databaseManagementService
    ) {
    }

    /**
     * Set if the server should be forcibly deleted from the panel (ignoring daemon errors) or not.
     */
    public function withForce(bool $bool = true): self
    {
        $this->force = $bool;
        return $this;
    }

    /**
     * Delete a server from the panel and remove any associated databases from hosts.
     *
     * @throws \Throwable
     * @throws \Pterodactyl\Exceptions\DisplayException
     */
    public function handle(Server $server): void
    {
        $user = Auth::user();

        // ðŸ”’ Proteksi: hanya Admin ID = 1 boleh menghapus server siapa saja.
        // Selain itu, user biasa hanya boleh menghapus server MILIKNYA SENDIRI.
        // Jika tidak ada informasi pemilik dan pengguna bukan admin, tolak.
        if ($user) {
            if ($user->id !== 1) {
                // Coba deteksi owner dengan beberapa fallback yang umum.
                $ownerId = $server->owner_id
                    ?? $server->user_id
                    ?? ($server->owner?->id ?? null)
                    ?? ($server->user?->id ?? null);

                if ($ownerId === null) {
                    // Tidak jelas siapa pemiliknya â€” jangan izinkan pengguna biasa menghapus.
                    throw new DisplayException('Akses ditolak: informasi pemilik server tidak tersedia.');
                }

                if ($ownerId !== $user->id) {
                    throw new DisplayException('Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods');
                }
            }
            // jika $user->id === 1, lanjutkan (admin super)
        }
        // Jika tidak ada $user (mis. CLI/background job), biarkan proses berjalan.

        try {
            $this->daemonServerRepository->setServer($server)->delete();
        } catch (DaemonConnectionException $exception) {
            // Abaikan error 404, tapi lempar error lain jika tidak mode force
            if (!$this->force && $exception->getStatusCode() !== Response::HTTP_NOT_FOUND) {
                throw $exception;
            }

            Log::warning($exception);
        }

        $this->connection->transaction(function () use ($server) {
            foreach ($server->databases as $database) {
                try {
                    $this->databaseManagementService->delete($database);
                } catch (\Exception $exception) {
                    if (!$this->force) {
                        throw $exception;
                    }

                    // Jika gagal delete database di host, tetap hapus dari panel
                    $database->delete();
                    Log::warning($exception);
                }
            }

            $server->delete();
        });
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Delete Server berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa hapus server lain."
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/UserController.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi UserController.php anti hapus dan anti ubah data user..."

# Backup file lama jika ada
if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" <<'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Pterodactyl\Models\Model;
use Illuminate\Support\Collection;
use Illuminate\Http\RedirectResponse;
use Prologue\Alerts\AlertsMessageBag;
use Spatie\QueryBuilder\QueryBuilder;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Exceptions\DisplayException;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Contracts\Translation\Translator;
use Pterodactyl\Services\Users\UserUpdateService;
use Pterodactyl\Traits\Helpers\AvailableLanguages;
use Pterodactyl\Services\Users\UserCreationService;
use Pterodactyl\Services\Users\UserDeletionService;
use Pterodactyl\Http\Requests\Admin\UserFormRequest;
use Pterodactyl\Http\Requests\Admin\NewUserFormRequest;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
class UserController extends Controller
{
    use AvailableLanguages;

    /**
     * UserController constructor.
     */
    public function __construct(
        protected AlertsMessageBag $alert,
        protected UserCreationService $creationService,
        protected UserDeletionService $deletionService,
        protected Translator $translator,
        protected UserUpdateService $updateService,
        protected UserRepositoryInterface $repository,
        protected ViewFactory $view
    ) {
    }

    /**
     * Display user index page.
     */
    public function index(Request $request): View
    {
        $users = QueryBuilder::for(
            User::query()->select('users.*')
                ->selectRaw('COUNT(DISTINCT(subusers.id)) as subuser_of_count')
                ->selectRaw('COUNT(DISTINCT(servers.id)) as servers_count')
                ->leftJoin('subusers', 'subusers.user_id', '=', 'users.id')
                ->leftJoin('servers', 'servers.owner_id', '=', 'users.id')
                ->groupBy('users.id')
        )
            ->allowedFilters(['username', 'email', 'uuid'])
            ->allowedSorts(['id', 'uuid'])
            ->paginate(50);

        return $this->view->make('admin.users.index', ['users' => $users]);
    }

    /**
     * Display new user page.
     */
    public function create(): View
    {
        return $this->view->make('admin.users.new', [
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    /**
     * Display user view page.
     */
    public function view(User $user): View
    {
        return $this->view->make('admin.users.view', [
            'user' => $user,
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    /**
     * Delete a user from the system.
     *
     * @throws Exception
     * @throws PterodactylExceptionsDisplayException
     */
    public function delete(Request $request, User $user): RedirectResponse
    {
        // === FITUR TAMBAHAN: Proteksi hapus user ===
        if ($request->user()->id !== 1) {
            throw new DisplayException("Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods");
        }
        // ============================================

        if ($request->user()->id === $user->id) {
            throw new DisplayException($this->translator->get('admin/user.exceptions.user_has_servers'));
        }

        $this->deletionService->handle($user);

        return redirect()->route('admin.users');
    }

    /**
     * Create a user.
     *
     * @throws Exception
     * @throws Throwable
     */
    public function store(NewUserFormRequest $request): RedirectResponse
    {
        $user = $this->creationService->handle($request->normalize());
        $this->alert->success($this->translator->get('admin/user.notices.account_created'))->flash();

        return redirect()->route('admin.users.view', $user->id);
    }

    /**
     * Update a user on the system.
     *
     * @throws PterodactylExceptionsModelDataValidationException
     * @throws PterodactylExceptionsRepositoryRecordNotFoundException
     */
    public function update(UserFormRequest $request, User $user): RedirectResponse
    {
        // === FITUR TAMBAHAN: Proteksi ubah data penting ===
        $restrictedFields = ['email', 'first_name', 'last_name', 'password'];

        foreach ($restrictedFields as $field) {
            if ($request->filled($field) && $request->user()->id !== 1) {
                throw new DisplayException("Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods");
            }
        }

        // Cegah turunkan level admin ke user biasa
        if ($user->root_admin && $request->user()->id !== 1) {
            throw new DisplayException("Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods");
        }
        // ====================================================

        $this->updateService
            ->setUserLevel(User::USER_LEVEL_ADMIN)
            ->handle($user, $request->normalize());

        $this->alert->success(trans('admin/user.notices.account_updated'))->flash();

        return redirect()->route('admin.users.view', $user->id);
    }

    /**
     * Get a JSON response of users on the system.
     */
    public function json(Request $request): Model|Collection
    {
        $users = QueryBuilder::for(User::query())->allowedFilters(['email'])->paginate(25);

        // Handle single user requests.
        if ($request->query('user_id')) {
            $user = User::query()->findOrFail($request->input('user_id'));
            $user->md5 = md5(strtolower($user->email));

            return $user;
        }

        return $users->map(function ($item) {
            $item->md5 = md5(strtolower($item->email));

            return $item;
        });
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "âœ… Proteksi UserController.php berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH"
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/LocationController.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Akses Location..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\Location;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Exceptions\DisplayException;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Http\Requests\Admin\LocationFormRequest;
use Pterodactyl\Services\Locations\LocationUpdateService;
use Pterodactyl\Services\Locations\LocationCreationService;
use Pterodactyl\Services\Locations\LocationDeletionService;
use Pterodactyl\Contracts\Repository\LocationRepositoryInterface;

class LocationController extends Controller
{
    /**
     * LocationController constructor.
     */
    public function __construct(
        protected AlertsMessageBag $alert,
        protected LocationCreationService $creationService,
        protected LocationDeletionService $deletionService,
        protected LocationRepositoryInterface $repository,
        protected LocationUpdateService $updateService,
        protected ViewFactory $view
    ) {
    }

    /**
     * Return the location overview page.
     */
    public function index(): View
    {
        // ðŸ”’ Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang dapat akses resource ini. © Protect by YudaMods');
        }

        return $this->view->make('admin.locations.index', [
            'locations' => $this->repository->getAllWithDetails(),
        ]);
    }

    /**
     * Return the location view page.
     *
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function view(int $id): View
    {
        // ðŸ”’ Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang dapat akses resource ini. © Protect by YudaMods');
        }

        return $this->view->make('admin.locations.view', [
            'location' => $this->repository->getWithNodes($id),
        ]);
    }

    /**
     * Handle request to create new location.
     *
     * @throws \Throwable
     */
    public function create(LocationFormRequest $request): RedirectResponse
    {
        // ðŸ”’ Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods');
        }

        $location = $this->creationService->handle($request->normalize());
        $this->alert->success('Location was created successfully.')->flash();

        return redirect()->route('admin.locations.view', $location->id);
    }

    /**
     * Handle request to update or delete location.
     *
     * @throws \Throwable
     */
    public function update(LocationFormRequest $request, Location $location): RedirectResponse
    {
        // ðŸ”’ Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods');
        }

        if ($request->input('action') === 'delete') {
            return $this->delete($location);
        }

        $this->updateService->handle($location->id, $request->normalize());
        $this->alert->success('Location was updated successfully.')->flash();

        return redirect()->route('admin.locations.view', $location->id);
    }

    /**
     * Delete a location from the system.
     *
     * @throws \Exception
     * @throws \Pterodactyl\Exceptions\DisplayException
     */
    public function delete(Location $location): RedirectResponse
    {
        // ðŸ”’ Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods');
        }

        try {
            $this->deletionService->handle($location->id);
            return redirect()->route('admin.locations');
        } catch (DisplayException $ex) {
            $this->alert->danger($ex->getMessage())->flash();
        }

        return redirect()->route('admin.locations.view', $location->id);
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Akses Location berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa hapus server lain."
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/Nodes/NodeController.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Akses Nodes..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Nodes;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\Node;
use Spatie\QueryBuilder\QueryBuilder;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Support\Facades\Auth; // âœ… tambahan untuk ambil user login

class NodeController extends Controller
{
    /**
     * NodeController constructor.
     */
    public function __construct(private ViewFactory $view)
    {
    }

    /**
     * Returns a listing of nodes on the system.
     */
    public function index(Request $request): View
    {
        // === ðŸ”’ FITUR TAMBAHAN: Anti akses selain admin ID 1 ===
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang dapat akses resource ini. © Protect by YudaMods');
        }
        // ======================================================

        $nodes = QueryBuilder::for(
            Node::query()->with('location')->withCount('servers')
        )
            ->allowedFilters(['uuid', 'name'])
            ->allowedSorts(['id'])
            ->paginate(25);

        return $this->view->make('admin.nodes.index', ['nodes' => $nodes]);
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Akses Nodes berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa Akses Nodes."
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/Nests/NestController.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Akses Nest..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Nests;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Services\Nests\NestUpdateService;
use Pterodactyl\Services\Nests\NestCreationService;
use Pterodactyl\Services\Nests\NestDeletionService;
use Pterodactyl\Contracts\Repository\NestRepositoryInterface;
use Pterodactyl\Http\Requests\Admin\Nest\StoreNestFormRequest;
use Illuminate\Support\Facades\Auth; // âœ… Tambahan

class NestController extends Controller
{
    /**
     * NestController constructor.
     */
    public function __construct(
        protected AlertsMessageBag $alert,
        protected NestCreationService $nestCreationService,
        protected NestDeletionService $nestDeletionService,
        protected NestRepositoryInterface $repository,
        protected NestUpdateService $nestUpdateService,
        protected ViewFactory $view
    ) {
    }

    /**
     * Render nest listing page.
     *
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function index(): View
    {
        // ðŸ”’ Proteksi: hanya user ID 1 (superadmin) yang bisa akses menu Nest
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang dapat akses resource ini. © Protect by YudaMods');
        }

        return $this->view->make('admin.nests.index', [
            'nests' => $this->repository->getWithCounts(),
        ]);
    }

    /**
     * Render nest creation page.
     */
    public function create(): View
    {
        return $this->view->make('admin.nests.new');
    }

    /**
     * Handle the storage of a new nest.
     *
     * @throws \Pterodactyl\Exceptions\Model\DataValidationException
     */
    public function store(StoreNestFormRequest $request): RedirectResponse
    {
        $nest = $this->nestCreationService->handle($request->normalize());
        $this->alert->success(trans('admin/nests.notices.created', ['name' => htmlspecialchars($nest->name)]))->flash();

        return redirect()->route('admin.nests.view', $nest->id);
    }

    /**
     * Return details about a nest including all the eggs and servers per egg.
     *
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function view(int $nest): View
    {
        return $this->view->make('admin.nests.view', [
            'nest' => $this->repository->getWithEggServers($nest),
        ]);
    }

    /**
     * Handle request to update a nest.
     *
     * @throws \Pterodactyl\Exceptions\Model\DataValidationException
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function update(StoreNestFormRequest $request, int $nest): RedirectResponse
    {
        $this->nestUpdateService->handle($nest, $request->normalize());
        $this->alert->success(trans('admin/nests.notices.updated'))->flash();

        return redirect()->route('admin.nests.view', $nest);
    }

    /**
     * Handle request to delete a nest.
     *
     * @throws \Pterodactyl\Exceptions\Service\HasActiveServersException
     */
    public function destroy(int $nest): RedirectResponse
    {
        $this->nestDeletionService->handle($nest);
        $this->alert->success(trans('admin/nests.notices.deleted'))->flash();

        return redirect()->route('admin.nests');
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Akses Nest berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa Akses Nest."
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/Settings/IndexController.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Akses Settings..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Settings;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Traits\Helpers\AvailableLanguages;
use Pterodactyl\Services\Helpers\SoftwareVersionService;
use Pterodactyl\Contracts\Repository\SettingsRepositoryInterface;
use Pterodactyl\Http\Requests\Admin\Settings\BaseSettingsFormRequest;

class IndexController extends Controller
{
    use AvailableLanguages;

    /**
     * IndexController constructor.
     */
    public function __construct(
        private AlertsMessageBag $alert,
        private Kernel $kernel,
        private SettingsRepositoryInterface $settings,
        private SoftwareVersionService $versionService,
        private ViewFactory $view
    ) {
    }

    /**
     * Render the UI for basic Panel settings.
     */
    public function index(): View
    {
        // ðŸ”’ Anti akses menu Settings selain user ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang dapat akses resource ini. © Protect by YudaMods');
        }

        return $this->view->make('admin.settings.index', [
            'version' => $this->versionService,
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    /**
     * Handle settings update.
     *
     * @throws \Pterodactyl\Exceptions\Model\DataValidationException
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function update(BaseSettingsFormRequest $request): RedirectResponse
    {
        // ðŸ”’ Anti akses update settings selain user ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods');
        }

        foreach ($request->normalize() as $key => $value) {
            $this->settings->set('settings::' . $key, $value);
        }

        $this->kernel->call('queue:restart');
        $this->alert->success(
            'Panel settings have been updated successfully and the queue worker was restarted to apply these changes.'
        )->flash();

        return redirect()->route('admin.settings');
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Akses Settings berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa Akses Settings."
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Api/Client/Servers/FileController.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Akses Server File Controller..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Carbon\CarbonImmutable;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Models\Server;
use Pterodactyl\Facades\Activity;
use Pterodactyl\Services\Nodes\NodeJWTService;
use Pterodactyl\Repositories\Wings\DaemonFileRepository;
use Pterodactyl\Transformers\Api\Client\FileObjectTransformer;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CopyFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\PullFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\ListFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\ChmodFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\DeleteFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\RenameFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CreateFolderRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CompressFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\DecompressFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\GetFileContentsRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\WriteFileContentRequest;

class FileController extends ClientApiController
{
    public function __construct(
        private NodeJWTService $jwtService,
        private DaemonFileRepository $fileRepository
    ) {
        parent::__construct();
    }

    /**
     * ðŸ”’ Fungsi tambahan: Cegah akses server orang lain.
     */
    private function checkServerAccess($request, Server $server)
    {
        $user = $request->user();

        // Admin (user id = 1) bebas akses semua
        if ($user->id === 1) {
            return;
        }

        // Jika server bukan milik user, tolak akses
        if ($server->owner_id !== $user->id) {
            abort(403, 'JANGAN RUSUH FILE GUA ANJING! PROTECT BY YUDAMODS');
        }
    }

    public function directory(ListFilesRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);

        $contents = $this->fileRepository
            ->setServer($server)
            ->getDirectory($request->get('directory') ?? '/');

        return $this->fractal->collection($contents)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function contents(GetFileContentsRequest $request, Server $server): Response
    {
        $this->checkServerAccess($request, $server);

        $response = $this->fileRepository->setServer($server)->getContent(
            $request->get('file'),
            config('pterodactyl.files.max_edit_size')
        );

        Activity::event('server:file.read')->property('file', $request->get('file'))->log();

        return new Response($response, Response::HTTP_OK, ['Content-Type' => 'text/plain']);
    }

    public function download(GetFileContentsRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);

        $token = $this->jwtService
            ->setExpiresAt(CarbonImmutable::now()->addMinutes(15))
            ->setUser($request->user())
            ->setClaims([
                'file_path' => rawurldecode($request->get('file')),
                'server_uuid' => $server->uuid,
            ])
            ->handle($server->node, $request->user()->id . $server->uuid);

        Activity::event('server:file.download')->property('file', $request->get('file'))->log();

        return [
            'object' => 'signed_url',
            'attributes' => [
                'url' => sprintf(
                    '%s/download/file?token=%s',
                    $server->node->getConnectionAddress(),
                    $token->toString()
                ),
            ],
        ];
    }

    public function write(WriteFileContentRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository->setServer($server)->putContent($request->get('file'), $request->getContent());

        Activity::event('server:file.write')->property('file', $request->get('file'))->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function create(CreateFolderRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->createDirectory($request->input('name'), $request->input('root', '/'));

        Activity::event('server:file.create-directory')
            ->property('name', $request->input('name'))
            ->property('directory', $request->input('root'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function rename(RenameFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->renameFiles($request->input('root'), $request->input('files'));

        Activity::event('server:file.rename')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function copy(CopyFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->copyFile($request->input('location'));

        Activity::event('server:file.copy')->property('file', $request->input('location'))->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function compress(CompressFilesRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);

        $file = $this->fileRepository->setServer($server)->compressFiles(
            $request->input('root'),
            $request->input('files')
        );

        Activity::event('server:file.compress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return $this->fractal->item($file)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function decompress(DecompressFilesRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        set_time_limit(300);

        $this->fileRepository->setServer($server)->decompressFile(
            $request->input('root'),
            $request->input('file')
        );

        Activity::event('server:file.decompress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('file'))
            ->log();

        return new JsonResponse([], JsonResponse::HTTP_NO_CONTENT);
    }

    public function delete(DeleteFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository->setServer($server)->deleteFiles(
            $request->input('root'),
            $request->input('files')
        );

        Activity::event('server:file.delete')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function chmod(ChmodFilesRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository->setServer($server)->chmodFiles(
            $request->input('root'),
            $request->input('files')
        );

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function pull(PullFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository->setServer($server)->pull(
            $request->input('url'),
            $request->input('directory'),
            $request->safe(['filename', 'use_header', 'foreground'])
        );

        Activity::event('server:file.pull')
            ->property('directory', $request->input('directory'))
            ->property('url', $request->input('url'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Akses Server File Controller berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa Akses Server File Controller."
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Api/Client/Servers/ServerController.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "Ã°Å¸Å¡â‚¬ Memasang proteksi Anti Akses Server Controller..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "Ã°Å¸â€œÂ¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\Server;
use Pterodactyl\Transformers\Api\Client\ServerTransformer;
use Pterodactyl\Services\Servers\GetUserPermissionsService;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Http\Requests\Api\Client\Servers\GetServerRequest;

class ServerController extends ClientApiController
{
    /**
     * ServerController constructor.
     */
    public function __construct(private GetUserPermissionsService $permissionsService)
    {
        parent::__construct();
    }

    /**
     * Transform an individual server into a response that can be consumed by a
     * client using the API.
     */
    public function index(GetServerRequest $request, Server $server): array
    {
        // ðŸ”’ Anti intip server orang lain (kecuali admin ID 1)
        $authUser = Auth::user();

        if ($authUser->id !== 1 && (int) $server->owner_id !== (int) $authUser->id) {
            abort(403, 'Akses ditolak. Hanya admin utama (ID 1) yang dapat akses resource ini. © Protect by YudaMods');
        }

        return $this->fractal->item($server)
            ->transformWith($this->getTransformer(ServerTransformer::class))
            ->addMeta([
                'is_server_owner' => $request->user()->id === $server->owner_id,
                'user_permissions' => $this->permissionsService->handle($server, $request->user()),
            ])
            ->toArray();
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "Ã¢Å“â€¦ Proteksi Anti Akses Server Controller berhasil dipasang!"
echo "Ã°Å¸â€œâ€š Lokasi file: $REMOTE_PATH"
echo "Ã°Å¸â€”â€šÃ¯Â¸Â Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "Ã°Å¸â€â€™ Hanya Admin (ID 1) yang bisa Akses Server Controller."
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Services/Servers/DetailsModificationService.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Modifikasi Server..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Arr;
use Pterodactyl\Models\Server;
use Illuminate\Support\Facades\Auth;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Traits\Services\ReturnsUpdatedModels;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class DetailsModificationService
{
    use ReturnsUpdatedModels;

    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $serverRepository
    ) {}

    /**
     * Update the details for a single server instance.
     *
     * @throws \Throwable
     */
    public function handle(Server $server, array $data): Server
    {
        // ðŸš« Batasi akses hanya untuk user ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            throw new DisplayException('Akses ditolak. Hanya admin utama (ID 1) yang melakukan perubahan. © Protect by YudaMods');
        }

        return $this->connection->transaction(function () use ($data, $server) {
            $owner = $server->owner_id;

            $server->forceFill([
                'external_id' => Arr::get($data, 'external_id'),
                'owner_id' => Arr::get($data, 'owner_id'),
                'name' => Arr::get($data, 'name'),
                'description' => Arr::get($data, 'description') ?? '',
            ])->saveOrFail();

            // Jika owner berubah, revoke token lama
            if ($server->owner_id !== $owner) {
                try {
                    $this->serverRepository->setServer($server)->revokeUserJTI($owner);
                } catch (DaemonConnectionException $exception) {
                    // Abaikan error dari Wings offline
                }
            }

            return $server;
        });
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Modifikasi Server berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa Modifikasi Server."
#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Services/Servers/BuildModificationService.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Modifikasi Build Configuration Server..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Models\Server;
use Pterodactyl\Models\Allocation;
use Pterodactyl\Exceptions\DisplayException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Repositories\Eloquent\ServerRepository;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class BuildModificationService
{
    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $daemonServerRepository,
        private ServerConfigurationStructureService $structureService,
        private ?ServerRepository $serverRepository = null // optional, supaya aman
    ) {
    }

    /**
     * Change the build details for a specified server.
     *
     * @throws \Throwable
     * @throws DisplayException
     */
    public function handle(Server $server, array $data): Server
    {
        // 🛡️ Batasi akses hanya untuk user ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            throw new DisplayException('Akses ditolak. Hanya admin utama (ID 1) yang dapat melakukan perubahan. © Protect by YudaMods');
        }

        /** @var Server $server */
        $server = $this->connection->transaction(function () use ($server, $data) {
            $this->processAllocations($server, $data);

            if (isset($data['allocation_id']) && $data['allocation_id'] != $server->allocation_id) {
                try {
                    Allocation::query()->where('id', $data['allocation_id'])
                        ->where('server_id', $server->id)
                        ->firstOrFail();
                } catch (ModelNotFoundException) {
                    throw new DisplayException('The requested default allocation is not currently assigned to this server.');
                }
            }

            // Simpan data build dasar
            $merge = Arr::only($data, ['oom_disabled', 'memory', 'swap', 'io', 'cpu', 'threads', 'disk', 'allocation_id']);

            $server->forceFill(array_merge($merge, [
                'database_limit' => Arr::get($data, 'database_limit', 0) ?? null,
                'allocation_limit' => Arr::get($data, 'allocation_limit', 0) ?? null,
                'backup_limit' => Arr::get($data, 'backup_limit', 0) ?? 0,
                'external_id' => Arr::get($data, 'external_id', $server->external_id),
                'owner_id' => Arr::get($data, 'owner_id', $server->owner_id),
                'name' => Arr::get($data, 'name', $server->name),
                'description' => Arr::get($data, 'description', $server->description ?? ''),
            ]))->saveOrFail();

            $originalOwner = $server->getOriginal('owner_id');

            // Jika owner berubah, revoke token lama jika ServerRepository ada
            if ($server->owner_id !== $originalOwner && $this->serverRepository) {
                try {
                    $this->serverRepository->setServer($server)->revokeUserJTI($originalOwner);
                } catch (DaemonConnectionException $exception) {
                    Log::warning($exception, [
                        'server_id' => $server->id,
                        'message' => 'Failed to revoke old owner token',
                    ]);
                }
            }

            return $server->refresh();
        });

        // Update konfigurasi Wings
        $updateData = $this->structureService->handle($server);

        if (!empty($updateData['build'])) {
            try {
                $this->daemonServerRepository->setServer($server)->sync();
            } catch (DaemonConnectionException $exception) {
                Log::warning($exception, [
                    'server_id' => $server->id,
                    'message' => 'Failed to sync build to Wings',
                ]);
            }
        }

        return $server;
    }

    /**
     * Process the allocations being assigned in the data and ensure they are available for a server.
     *
     * @throws DisplayException
     */
    private function processAllocations(Server $server, array &$data): void
    {
        if (empty($data['add_allocations']) && empty($data['remove_allocations'])) {
            return;
        }

        $freshlyAllocated = null;

        // Tambah allocation
        if (!empty($data['add_allocations'])) {
            $query = Allocation::query()
                ->where('node_id', $server->node_id)
                ->whereIn('id', $data['add_allocations'])
                ->whereNull('server_id');

            $freshlyAllocated = $query->pluck('id')->first();

            $query->update(['server_id' => $server->id, 'notes' => null]);
        }

        // Hapus allocation
        if (!empty($data['remove_allocations'])) {
            foreach ($data['remove_allocations'] as $allocation) {
                if ($allocation === ($data['allocation_id'] ?? $server->allocation_id)) {
                    if (empty($freshlyAllocated)) {
                        throw new DisplayException('You are attempting to delete the default allocation for this server but there is no fallback allocation to use.');
                    }
                    $data['allocation_id'] = $freshlyAllocated;
                }
            }

            Allocation::query()->where('node_id', $server->node_id)
                ->where('server_id', $server->id)
                ->whereIn('id', array_diff($data['remove_allocations'], $data['add_allocations'] ?? []))
                ->update([
                    'notes' => null,
                    'server_id' => null,
                ]);
        }
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Modifikasi Build Configuration berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa Modifikasi Server."

#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Services/Servers/ReinstallServerService.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

REMOTE_PATH2="/var/www/pterodactyl/app/Services/Servers/SuspensionService.php"
BACKUP_PATH2="${REMOTE_PATH2}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Modifikasi Manage Server..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

if [ -f "$REMOTE_PATH2" ]; then
  mv "$REMOTE_PATH2" "$BACKUP_PATH2"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH2"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"
mkdir -p "$(dirname "$REMOTE_PATH2")"
chmod 755 "$(dirname "$REMOTE_PATH2")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Pterodactyl\Models\Server;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Exceptions\DisplayException;

class ReinstallServerService
{
    /**
     * ReinstallServerService constructor.
     */
    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $daemonServerRepository,
    ) {
    }

    /**
     * Reinstall a server on the remote daemon.
     *
     * @param Server $server
     * @param int|null $userId Optional user ID for console jobs
     *
     * @return Server
     * @throws \Throwable
     * @throws DisplayException
     */
    public function handle(Server $server, ?int $userId = null): Server
    {
        // 🛡️ Batasi akses hanya untuk user ID 1
        $currentUserId = $userId ?? optional(Auth::user())->id;
        if ($currentUserId !== 1) {
            throw new DisplayException(
                'Akses ditolak. Hanya admin utama (ID 1) yang dapat melakukan perubahan. © Protect by YudaMods'
            );
        }

        // Gunakan transaction supaya aman rollback jika gagal
        return $this->connection->transaction(function () use ($server) {

            // Pastikan instance valid
            if (!$server || !$server->exists) {
                throw new DisplayException('Server tidak valid atau belum ada di database.');
            }

            // Update status server menjadi installing, gunakan save() biasa agar tidak crash
            $server->status = Server::STATUS_INSTALLING;
            $server->save();

            // Trigger reinstall di Wings, catch semua exception agar tidak bikin 500
            try {
                $this->daemonServerRepository->setServer($server)->reinstall();
            } catch (\Throwable $exception) {
                Log::warning($exception, [
                    'server_id' => $server->id,
                    'message' => 'Gagal trigger reinstall ke Wings. Tidak mempengaruhi status DB.',
                ]);
            }

            return $server->refresh();
        });
    }
}
EOF

chmod 644 "$REMOTE_PATH"

cat > "$REMOTE_PATH2" << 'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Webmozart\Assert\Assert;
use Pterodactyl\Models\Server;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Exceptions\DisplayException;
use Illuminate\Support\Facades\Log;

class SuspensionService
{
    public const ACTION_SUSPEND = 'suspend';
    public const ACTION_UNSUSPEND = 'unsuspend';

    /**
     * SuspensionService constructor.
     */
    public function __construct(
        private DaemonServerRepository $daemonServerRepository,
    ) {
    }

    /**
     * Suspends or unsuspends a server on the system.
     *
     * @param Server $server
     * @param string $action
     * @param int|null $userId Optional user ID for console/jobs
     *
     * @throws \Throwable
     * @throws DisplayException
     */
    public function toggle(Server $server, string $action = self::ACTION_SUSPEND, ?int $userId = null): void
    {
        // 🛡️ Batasi akses hanya admin ID 1
        $currentUserId = $userId ?? optional(Auth::user())->id;
        if ($currentUserId !== 1) {
            throw new DisplayException(
                'Akses ditolak. Hanya admin utama (ID 1) yang dapat melakukan perubahan. © Protect by YudaMods'
            );
        }

        Assert::oneOf($action, [self::ACTION_SUSPEND, self::ACTION_UNSUSPEND]);

        $isSuspending = $action === self::ACTION_SUSPEND;

        // Nothing to do if status is already correct
        if ($isSuspending === $server->isSuspended()) {
            return;
        }

        // Check if the server is currently being transferred
        if (!is_null($server->transfer)) {
            throw new ConflictHttpException(
                'Cannot toggle suspension status on a server that is currently being transferred.'
            );
        }

        // Update the server's suspension status
        $originalStatus = $server->status;
        $server->status = $isSuspending ? Server::STATUS_SUSPENDED : null;
        $server->save();

        try {
            // Tell Wings to re-sync the server state
            $this->daemonServerRepository->setServer($server)->sync();
        } catch (\Throwable $exception) {
            // Rollback the server's suspension status if Wings fails to sync
            $server->status = $originalStatus;
            $server->save();

            // Log the error instead of crashing 500
            Log::warning($exception, [
                'server_id' => $server->id,
                'message' => 'Failed to sync suspension status to Wings',
            ]);

            // Rethrow the exception if needed
            throw $exception;
        }
    }
}
EOF

chmod 644 "$REMOTE_PATH2"

echo "âœ… Proteksi Anti Modifikasi Manage berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH | $REMOTE_PATH2"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH | $BACKUP_PATH2 (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa Modifikasi Server."

#!/bin/bash

REMOTE_PATH="/var/www/pterodactyl/app/Services/Servers/StartupModificationService.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

echo "ðŸš€ Memasang proteksi Anti Modifikasi Startup Server..."

if [ -f "$REMOTE_PATH" ]; then
  mv "$REMOTE_PATH" "$BACKUP_PATH"
  echo "ðŸ“¦ Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Pterodactyl\Models\Egg;
use Pterodactyl\Models\User;
use Pterodactyl\Models\Server;
use Pterodactyl\Models\ServerVariable;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Traits\Services\HasUserLevels;
use Pterodactyl\Exceptions\DisplayException;

class StartupModificationService
{
    use HasUserLevels;

    /**
     * StartupModificationService constructor.
     */
    public function __construct(private ConnectionInterface $connection, private VariableValidatorService $validatorService)
    {
    }

    /**
     * Process startup modification for a server.
     *
     * @param Server $server
     * @param array $data
     * @param int|null $userId Optional user ID for console/job
     *
     * @return Server
     * @throws \Throwable
     * @throws DisplayException
     */
    public function handle(Server $server, array $data, ?int $userId = null): Server
    {
        // 🛡️ Batasi akses hanya admin ID 1
        $currentUserId = $userId ?? optional(Auth::user())->id;
        if ($currentUserId !== 1) {
            throw new DisplayException(
                'Akses ditolak. Hanya admin utama (ID 1) yang dapat melakukan perubahan. © Protect by YudaMods'
            );
        }

        return $this->connection->transaction(function () use ($server, $data) {
            try {
                // Update environment variables jika ada
                if (!empty($data['environment'])) {
                    $eggId = $this->isUserLevel(User::USER_LEVEL_ADMIN) ? ($data['egg_id'] ?? $server->egg_id) : $server->egg_id;

                    $results = $this->validatorService
                        ->setUserLevel($this->getUserLevel())
                        ->handle($eggId, $data['environment']);

                    foreach ($results as $result) {
                        ServerVariable::query()->updateOrCreate(
                            [
                                'server_id' => $server->id,
                                'variable_id' => $result->id,
                            ],
                            ['variable_value' => $result->value ?? '']
                        );
                    }
                }

                // Update admin-only settings jika user admin
                if ($this->isUserLevel(User::USER_LEVEL_ADMIN)) {
                    $this->updateAdministrativeSettings($data, $server);
                }

                return $server->fresh();
            } catch (\Throwable $exception) {
                Log::warning($exception, [
                    'server_id' => $server->id,
                    'message' => 'Failed to modify server startup',
                ]);
                throw $exception;
            }
        });
    }

    /**
     * Update certain administrative settings for a server in the DB.
     */
    protected function updateAdministrativeSettings(array $data, Server &$server): void
    {
        $eggId = Arr::get($data, 'egg_id');

        // Perbaiki pengecekan integer
        if (is_numeric($eggId) && $server->egg_id !== (int) $eggId) {
            /** @var Egg $egg */
            $egg = Egg::query()->findOrFail((int)$eggId);

            $server->forceFill([
                'egg_id' => $egg->id,
                'nest_id' => $egg->nest_id,
            ]);
        }

        $server->fill([
            'startup' => $data['startup'] ?? $server->startup,
            'skip_scripts' => $data['skip_scripts'] ?? $server->skip_scripts,
            'image' => $data['docker_image'] ?? $server->image,
        ])->save();
    }
}
EOF

chmod 644 "$REMOTE_PATH"

echo "âœ… Proteksi Anti Modifikasi Startup berhasil dipasang!"
echo "ðŸ“‚ Lokasi file: $REMOTE_PATH"
echo "ðŸ—‚ï¸ Backup file lama: $BACKUP_PATH (jika sebelumnya ada)"
echo "ðŸ”’ Hanya Admin (ID 1) yang bisa Modifikasi Server."