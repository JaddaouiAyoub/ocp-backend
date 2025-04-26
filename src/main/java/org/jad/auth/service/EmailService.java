package org.jad.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendPasswordChangedNotification(String to) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("jaddaoui.salim@gmail.com"); // important

        message.setTo(to);
        message.setSubject("🔐 Changement de mot de passe - OCP");
        message.setText("Votre mot de passe a été modifié avec succès.\n\n"
                + "Si ce n'est pas vous, veuillez contacter immédiatement l'administration.");

        mailSender.send(message);
    }
}
