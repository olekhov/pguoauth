# pguoauth
Модуль для аутентификации на сторонних ресурсах через портал государственных услуг (ПГУ) России. [https://www.gosuslugi.ru]

Предназначен для автоматизации работы с сайтами, на которых можно аутентифицироваться чреез ПГУ.

Неполный список:
* [https://pgu.mos.ru](Портал государственных услуг г. Москвы)
* [https://rosreestr.ru](Росреестр)
* [https://nalog.ru](Федеральная налоговая служба)

## Принцип работы 
1. На сайте запрашиваются данные: X1, X2, X3.
2. В аутентификатор PGUAuthenticator передаются: логин, пароль, X1, X2, X3.
3. После проведения всех церемоний на выходе: L2tpatken, Y2, Y3, которые передаются на сайт.

Примеры использования - в каталоге examples
