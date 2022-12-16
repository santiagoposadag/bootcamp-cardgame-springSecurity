import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { HomeComponent } from './pages/home/home.component';
import { NewGameComponent } from './pages/new-game/new-game.component';
import { ListGameComponent } from './pages/list-game/list-game.component';

// route guard
import { AuthGuard } from './shared/guard/auth.guard';
import { BoardComponent } from './pages/board/board.component';
import { MenuComponent } from './pages/menu/menu.component';
import { LoginComponent } from './login/login.component';

const routes: Routes = [
  { path: '', redirectTo: '/menu', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'menu', component: MenuComponent},
  { path: 'home', component: HomeComponent},
  { path: 'new', component: NewGameComponent, canActivate: [AuthGuard] },
  { path: 'list', component: ListGameComponent, canActivate: [AuthGuard] },
  { path: 'board/:id', component: BoardComponent, canActivate: [AuthGuard] }

];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})

export class AppRoutingModule {}