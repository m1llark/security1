package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.service.UserService;
import ru.kata.spring.boot_security.demo.util.MyValidator;

import javax.validation.Valid;


// LOGIN: admin  PASSWORD: admin (ДЛЯ АДМИНА)
// LOGIN: user  PASSWORD: user (ДЛЯ ЮЗЕРА)




@Controller
@RequestMapping("/admin")
public class AdminController {
    private final UserService userService;

    private final MyValidator myValidator;
    @Autowired
    public AdminController(UserService userService, MyValidator myValidator) {
        this.userService = userService;

        this.myValidator = myValidator;
    }
    @GetMapping()
    public String AllUsers(ModelMap model) {
        model.addAttribute("users", userService.listUsers());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user =  (User) authentication.getPrincipal();
        System.out.println(user.getAuthorities());
        return "admin";
    }

    @GetMapping("/{id}")
    public String getUserById(@PathVariable("id") Long id, Model model) {
        model.addAttribute("user", userService.loadUserById(id));
        return "show";
    }
    @DeleteMapping("/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        userService.removeUserById(id);
        return "redirect:/admin";
    }
    @GetMapping("/edit/{id}")
    public String showUpdateForm(@PathVariable("id") long id, Model model) {
        User user = userService.loadUserById(id);
        model.addAttribute("user", user);
        return "update-user";
    }
    @PostMapping("/update/{id}")
    public String updateUser(@PathVariable("id") long id, @Valid User user,
                             BindingResult result, Model model) {
        myValidator.validate(user, result);
        if (result.hasErrors()) {
            user.setId(id);
            return "update-user";
        }

        userService.register(user);
        return "redirect:/admin";
    }


    @GetMapping("/login")
    public String loginPage() {
        return "/login";
    }

    @GetMapping("/registration")
    public String Registration(@ModelAttribute("user") User user) {

        return "/registration";
    }
    @PostMapping("/registration")
    public String performRegistration(@ModelAttribute("user") @Valid User user, BindingResult bindingResult) {
        myValidator.validate(user, bindingResult);
        if (bindingResult.hasErrors()) {
            return "/registration";
        }
        else {
            userService.register(user);
            return "redirect:/admin";
        }
    }



}
