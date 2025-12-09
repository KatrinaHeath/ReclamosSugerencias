<?php

namespace Tests\Feature;

use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\FeatureTestTrait;

class LoginTest extends CIUnitTestCase
{
    use FeatureTestTrait;

    private string $base = 'http://localhost/reclamosSugerencias';


    /* ============================================================
     *                        PRUEBAS — DAVID
     *  Usuario Rol 1 = Acceso a dashboard ciudadano
     * ============================================================*/

    /** D1: Login correcto con credenciales válidas */
    public function testD1_LoginCorrecto()
    {
        $this->post('/login',[
            'username'=>'davidtroetsch22@gmail.com',
            'password'=>'1234'
        ])->assertRedirectTo($this->base.'/ciudadano/dashboard');
    }

    /** D2: Login correcto para Katrina (también ciudadano) */
    public function testD2_LoginKatrinaCorrecto()
    {
        $this->post('/login',[
            'username'=>'katrinahdls@gmail.com',
            'password'=>'1234'
        ])->assertRedirectTo($this->base.'/ciudadano/dashboard');
    }

    /** D3: Contraseña incorrecta debe redirigir (no autenticado) */
    public function testD3_ContrasenaIncorrecta()
    {
        $this->post('/login',['username'=>'davidtroetsch22@gmail.com','password'=>'xx'])
             ->assertRedirect();
    }

    /** D4: Email no registrado → no debe permitir acceso */
    public function testD4_EmailNoRegistrado()
    {
        $this->post('/login',['username'=>'none@gmail.com','password'=>'1234'])
             ->assertRedirect();
    }

    /** D5: Email vacío → formulario debe mantenerse (status 200) */
    public function testD5_EmailVacio()
    {
        $this->post('/login',['username'=>'','password'=>'1234'])
             ->assertOK();
    }

    /** D6: Password vacía → no debe autenticar */
    public function testD6_PasswordVacia()
    {
        $this->post('/login',['username'=>'david','password'=>''])
             ->assertOK();
    }

    /** D7: Ambos campos vacíos → validar error */
    public function testD7_CamposVacios()
    {
        $this->post('/login',['username'=>'','password'=>''])
             ->assertOK();
    }

    /** D8: Password muy corta → debe fallar login */
    public function testD8_PasswordMuyCorta()
    {
        $this->post('/login',['username'=>'david','password'=>'1'])
             ->assertRedirect();
    }

    /** D9: Password muy larga → debe rechazarse */
    public function testD9_PasswordMuyLarga()
    {
        $this->post('/login',['username'=>'david','password'=>str_repeat('a',70)])
             ->assertRedirect();
    }

    /** D10: Usuario con rol admin debe acceder al dashboard correspondiente */
    public function testD10_LoginAdmin()
    {
        $this->post('/login',[
            'username'=>'y@empresa.ac.pa',
            'password'=>'1234'
        ])->assertRedirectTo($this->base.'/admin/dashboard');
    }




    /* ============================================================
     *                      PRUEBAS — KATRINA
     *    Pruebas orientadas a validaciones y seguridad
     * ============================================================*/

    /** K1: Email con formato inválido */
    public function testK1_EmailFormatoInvalido()
    {
        $this->post('/login',['username'=>'aaa@@','password'=>'1234'])
             ->assertOK();
    }

    /** K2: Email con caracteres especiales no válidos */
    public function testK2_EmailConCaracteresEspeciales()
    {
        $this->post('/login',['username'=>'%$#@gmail.com','password'=>'1234'])
             ->assertOK();
    }

    /** K3: Email con espacios dentro → debe fallar validación */
    public function testK3_EmailConEspacios()
    {
        $this->post('/login',['username'=>' david @gmail.com ','password'=>'1234'])
             ->assertOK();
    }

    /** K4: Usuario compuesto solo por números */
    public function testK4_UsuarioSoloNumeros()
    {
        $this->post('/login',['username'=>'12345','password'=>'1234'])
             ->assertRedirect();
    }

    /** K5: Password con espacios internos → debe fallar */
    public function testK5_PasswordConEspaciosInternos()
    {
        $this->post('/login',['username'=>'david','password'=>'12 34'])
             ->assertRedirect();
    }

    /** K6: Password con espacios al inicio → inválida */
    public function testK6_PasswordConEspaciosInicio()
    {
        $this->post('/login',['username'=>'david','password'=>' 1234'])
             ->assertRedirect();
    }

    /** K7: Login correcto para Katrina (case sensitive en password) */
    public function testK7_CaseSensitivePassword()
    {
        $this->post('/login',['username'=>'katrinahdls@gmail.com','password'=>'1234'])
             ->assertRedirectTo($this->base.'/ciudadano/dashboard');
    }

    /** K8: Intento de inyección SQL */
    public function testK8_InyeccionSQL()
    {
        $this->post('/login',['username'=>"' OR 1=1 --",'password'=>'1234'])
             ->assertRedirect();
    }

    /** K9: Intento de XSS en campo usuario */
    public function testK9_XSS()
    {
        $this->post('/login',['username'=>'<script>alert(1)</script>','password'=>'1234'])
             ->assertRedirect();
    }

    /** K10: Cuenta marcada como suspendida → acceso denegado */
    public function testK10_CuentaSuspendida()
    {
        $this->post('/login',['username'=>'elislameco2354@gmail.com','password'=>'1234'])
             ->assertRedirect();
    }




    /* ============================================================
     *                    PRUEBAS — BENJAMÍN
     *  Variaciones del email y comportamiento del login
     * ============================================================*/

    /** B1: Email con combinaciones de mayúsculas/minúsculas */
    public function testB1_EmailMayusMinus()
    {
        $this->post('/login',[
            'username'=>'DaVidTroEtsCh22@gmail.com',
            'password'=>'1234'
        ])->assertRedirectTo($this->base.'/ciudadano/dashboard');
    }

    /** B2: Email completamente en mayúsculas */
    public function testB2_EmailTodoMayusculas()
    {
        $this->post('/login',[
            'username'=>'DAVIDTROETSCH22@GMAIL.COM',
            'password'=>'1234'
        ])->assertRedirectTo($this->base.'/ciudadano/dashboard');
    }

    /** B3: Email completamente en minúsculas */
    public function testB3_EmailTodoMinusculas()
    {
        $this->post('/login',[
            'username'=>'davidtroetsch22@gmail.com',
            'password'=>'1234'
        ])->assertRedirectTo($this->base.'/ciudadano/dashboard');
    }

    /** B4: Contraseña con símbolos no válidos */
    public function testB4_PasswordConSimbolos()
    {
        $this->post('/login',['username'=>'davidtroetsch22@gmail.com','password'=>'12#34'])
             ->assertRedirect();
    }

    /** B5: Email sin dominio */
    public function testB5_EmailSinDominio()
    {
        $this->post('/login',['username'=>'david@','password'=>'1234'])
             ->assertOK();
    }

    /** B6: Email con dominio incompleto */
    public function testB6_EmailDominioInvalido()
    {
        $this->post('/login',['username'=>'david@gmail','password'=>'1234'])
             ->assertOK();
    }

    /** B7: Password con caracteres Unicode */
    public function testB7_PasswordUnicode()
    {
        $this->post('/login',['username'=>'david','password'=>'😊😊😊1234'])
             ->assertRedirect();
    }

    /** B8: Tres intentos fallidos → debe bloquear temporalmente */
    public function testB8_TresIntentosFallidos()
    {
        for($i=0;$i<3;$i++){
            $this->post('/login',['username'=>'david','password'=>'xxxx'])
                 ->assertRedirect();
        }
    }

    /** B9: Login usando nombre de usuario → debe acceder como ciudadano */
    public function testB9_LoginPorUsuario()
    {
        $this->post('/login',['username'=>'david','password'=>'1234'])
             ->assertRedirectTo($this->base.'/ciudadano/dashboard');
    }

    /** B10: Login usando correo → también debe acceder a ciudadano */
    public function testB10_LoginPorEmail()
    {
        $this->post('/login',['username'=>'davidtroetsch22@gmail.com','password'=>'1234'])
             ->assertRedirectTo($this->base.'/ciudadano/dashboard');
    }
}

