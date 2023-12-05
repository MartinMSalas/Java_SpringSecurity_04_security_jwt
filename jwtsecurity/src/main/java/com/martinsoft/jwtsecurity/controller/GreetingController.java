package com.martinsoft.jwtsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController

@RequestMapping("/api/greeting")
public class GreetingController{
    @GetMapping("/hello")
    public String hello(){
        return "Hello World";
    }
}
