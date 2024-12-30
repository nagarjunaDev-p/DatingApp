import { HttpClient } from '@angular/common/http';
import { Component, inject, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent implements OnInit{
  title = 'Dating App';
  http =inject(HttpClient)
  users:any;

  ngOnInit(): void {
    this.http.get('https://localhost:5001/api/Users').subscribe({
      next  : response => this.users = response,
      error : err => console.log(err),
      complete:()=> console.log('Request completed')
    })
  }
}