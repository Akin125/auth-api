from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0003_emailverificationtoken_passwordresettoken'),
    ]

    operations = [
        migrations.DeleteModel(
            name='APIKey',
        ),
    ]
