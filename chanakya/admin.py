from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django_otp.admin import OTPAdminSite
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_totp.admin import TOTPDeviceAdmin
from chanakya.models.conversation import ConversationModel, MessageModel, FeedbackModel
from chanakya.models.subscription_model import UserSubscription
from chanakya.models.prompts_model import PromptsModel
from chanakya.models.user import User
from django import forms
from chanakya.views.conversation_retrieve import SuperAdminRetrieveDataSet
from django.utils.decorators import method_decorator
from django.contrib.admin.views.decorators import staff_member_required


# Custom OTP Admin Site
class OTPAdmin(OTPAdminSite):
    pass


admin_site = OTPAdmin(name='OTPAdmin')
admin_site.register(TOTPDevice, TOTPDeviceAdmin)

admin_site.site_header = "Chanakya Admin"
admin_site.site_title = "Chanakya"
admin_site.index_title = "Welcome to Chanakya Admin"


# User Admin Configuration
class UserAdmin(BaseUserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
        (_('User Custom Info'), {
            'fields': ('preferred_language', 'task_interests', 'profile_bio', 'is_subscription_active', 'modified_at',
                       'date_of_birth')
        }),
    )
    add_fieldsets = (
        (None, {'classes': ('wide',), 'fields': ('username', 'password1', 'password2'), }),
    )
    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_active')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('username',)
    readonly_fields = ['modified_at']


admin_site.register(User, UserAdmin)


# admin.site.register(User, UserAdmin)


# Message Inline for Conversation
class MessageInline(admin.TabularInline):
    model = MessageModel
    extra = 1


# Date Range Form
class DateRangeForm(forms.Form):
    date_from = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    date_to = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))


# Conversation Admin
class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'user_email', 'created', 'updated')
    search_fields = ('title', 'user__email')
    inlines = [MessageInline]
    change_list_template = "retrieve_conversations.html"

    def user_email(self, obj):
        return obj.user.email

    user_email.short_description = 'User Email'

    @method_decorator(staff_member_required)
    def changelist_view(self, request, extra_context=None):
        form = DateRangeForm(request.POST or None)
        response_data = None

        if form.is_valid():
            date_from = form.cleaned_data['date_from']
            date_to = form.cleaned_data['date_to']
            retrieve_data = SuperAdminRetrieveDataSet(request)
            response_data = retrieve_data.retrieve_by_date(date_from, date_to)

        extra_context = extra_context or {'form': form, 'response': response_data}
        return super().changelist_view(request, extra_context=extra_context)


admin_site.register(ConversationModel, ConversationAdmin)


# Message Admin
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'content', 'role', 'user_email', 'conversation', 'created')
    search_fields = ('content', 'role', 'conversation__user__email')
    list_filter = ('role', 'conversation')
    ordering = ('-created',)

    def user_email(self, obj):
        return obj.conversation.user.email

    user_email.short_description = 'User Email'


admin_site.register(MessageModel, MessageAdmin)


# Prompts Admin
class PromptsModelAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'created_at', 'updated_at']
    search_fields = ['id', 'name']


admin_site.register(PromptsModel, PromptsModelAdmin)


# Feedback Admin
class FeedbackModelAdmin(admin.ModelAdmin):
    list_display = ['id', 'is_unliked', 'feedback', 'created', 'category']
    search_fields = ['id']


admin_site.register(FeedbackModel, FeedbackModelAdmin)


class UserSubscriptionAdmin(admin.ModelAdmin):
    list_display = ('user', 'provider_type', 'active', 'type', 'start_date', 'expiry_date', 'subscription_paused',
                    'subscription_cancel', 'request_id', 'transaction_id', 'period_type')
    search_fields = ('user__username', 'user__email')
    list_filter = ('provider_type', 'active', 'subscription_paused', 'subscription_cancel')
    # ordering = ('-start_date',)


admin_site.register(UserSubscription, UserSubscriptionAdmin)
