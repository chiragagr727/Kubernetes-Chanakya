# Generated by Django 5.0.6 on 2024-08-02 05:42

import django.contrib.auth.models
import django.contrib.auth.validators
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='PromptsModel',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('name', models.CharField(blank=True, max_length=100)),
                ('start_token', models.CharField(blank=True, max_length=100)),
                ('end_token', models.CharField(blank=True, max_length=100)),
                ('user_token', models.CharField(blank=True, max_length=100)),
                ('assistant_token', models.CharField(blank=True, max_length=100)),
                ('eot_token', models.CharField(blank=True, max_length=100)),
                ('system_message', models.CharField(blank=True, max_length=8000)),
                ('begin_of_text_token', models.CharField(blank=True, max_length=100)),
                ('system_token', models.CharField(blank=True, max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='email address')),
                ('mobile_no', models.CharField(blank=True, max_length=15, null=True)),
                ('preferred_language', models.CharField(blank=True, default=None, max_length=100, null=True)),
                ('task_interests', models.CharField(blank=True, default=None, max_length=100, null=True)),
                ('profile_bio', models.CharField(blank=True, default=None, max_length=100, null=True)),
                ('is_subscription_active', models.BooleanField(default=False, help_text="This field determines whether the user's subscription is active or inactive. Be cautious when changing this setting.")),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
                ('date_of_birth', models.DateField(blank=True, null=True, verbose_name='date of birth')),
                ('groups', models.ManyToManyField(blank=True, related_name='chanakya_user_set', to='auth.group')),
                ('user_permissions', models.ManyToManyField(blank=True, related_name='chanakya_user_set', to='auth.permission')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='ConversationModel',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('title', models.CharField(default='New Chat', max_length=100)),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('updated', models.DateTimeField(auto_now=True, verbose_name='updated')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='MessageModel',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('content', models.TextField()),
                ('role', models.CharField(choices=[('system', 'System'), ('user', 'User'), ('assistant', 'Assistant')], max_length=10)),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('updated', models.DateTimeField(auto_now=True, verbose_name='updated')),
                ('conversation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='chanakya.conversationmodel')),
            ],
        ),
        migrations.CreateModel(
            name='FeedbackModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('is_unliked', models.BooleanField(default=False)),
                ('feedback', models.TextField(default=None, null=True)),
                ('category', models.CharField(blank=True, default=None, max_length=30, null=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('message', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='message', to='chanakya.messagemodel')),
            ],
        ),
        migrations.CreateModel(
            name='UserSubscription',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('provider_type', models.CharField(choices=[('google', 'Google'), ('apple', 'Apple'), ('stripe', 'Stripe'), ('free', 'Free')], max_length=10)),
                ('active', models.BooleanField(default=True)),
                ('start_date', models.DateTimeField(auto_now_add=True)),
                ('expiry_date', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='subscriptions', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
