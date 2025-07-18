// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon QuickSight settings associated with your Amazon Web Services account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccountSettings {
    /// <p>The "account name" you provided for the Amazon QuickSight subscription in your Amazon Web Services account. You create this name when you sign up for Amazon QuickSight. It is unique in all of Amazon Web Services and it appears only when users sign in.</p>
    pub account_name: ::std::option::Option<::std::string::String>,
    /// <p>The edition of Amazon QuickSight that you're currently subscribed to: Enterprise edition or Standard edition.</p>
    pub edition: ::std::option::Option<crate::types::Edition>,
    /// <p>The default Amazon QuickSight namespace for your Amazon Web Services account.</p>
    pub default_namespace: ::std::option::Option<::std::string::String>,
    /// <p>The main notification email for your Amazon QuickSight subscription.</p>
    pub notification_email: ::std::option::Option<::std::string::String>,
    /// <p>A Boolean value that indicates whether public sharing is turned on for an Amazon QuickSight account. For more information about turning on public sharing, see <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_UpdatePublicSharingSettings.html">UpdatePublicSharingSettings</a>.</p>
    pub public_sharing_enabled: bool,
    /// <p>A boolean value that determines whether or not an Amazon QuickSight account can be deleted. A <code>True</code> value doesn't allow the account to be deleted and results in an error message if a user tries to make a <code>DeleteAccountSubsctiption</code> request. A <code>False</code> value will allow the ccount to be deleted.</p>
    pub termination_protection_enabled: bool,
}
impl AccountSettings {
    /// <p>The "account name" you provided for the Amazon QuickSight subscription in your Amazon Web Services account. You create this name when you sign up for Amazon QuickSight. It is unique in all of Amazon Web Services and it appears only when users sign in.</p>
    pub fn account_name(&self) -> ::std::option::Option<&str> {
        self.account_name.as_deref()
    }
    /// <p>The edition of Amazon QuickSight that you're currently subscribed to: Enterprise edition or Standard edition.</p>
    pub fn edition(&self) -> ::std::option::Option<&crate::types::Edition> {
        self.edition.as_ref()
    }
    /// <p>The default Amazon QuickSight namespace for your Amazon Web Services account.</p>
    pub fn default_namespace(&self) -> ::std::option::Option<&str> {
        self.default_namespace.as_deref()
    }
    /// <p>The main notification email for your Amazon QuickSight subscription.</p>
    pub fn notification_email(&self) -> ::std::option::Option<&str> {
        self.notification_email.as_deref()
    }
    /// <p>A Boolean value that indicates whether public sharing is turned on for an Amazon QuickSight account. For more information about turning on public sharing, see <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_UpdatePublicSharingSettings.html">UpdatePublicSharingSettings</a>.</p>
    pub fn public_sharing_enabled(&self) -> bool {
        self.public_sharing_enabled
    }
    /// <p>A boolean value that determines whether or not an Amazon QuickSight account can be deleted. A <code>True</code> value doesn't allow the account to be deleted and results in an error message if a user tries to make a <code>DeleteAccountSubsctiption</code> request. A <code>False</code> value will allow the ccount to be deleted.</p>
    pub fn termination_protection_enabled(&self) -> bool {
        self.termination_protection_enabled
    }
}
impl AccountSettings {
    /// Creates a new builder-style object to manufacture [`AccountSettings`](crate::types::AccountSettings).
    pub fn builder() -> crate::types::builders::AccountSettingsBuilder {
        crate::types::builders::AccountSettingsBuilder::default()
    }
}

/// A builder for [`AccountSettings`](crate::types::AccountSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccountSettingsBuilder {
    pub(crate) account_name: ::std::option::Option<::std::string::String>,
    pub(crate) edition: ::std::option::Option<crate::types::Edition>,
    pub(crate) default_namespace: ::std::option::Option<::std::string::String>,
    pub(crate) notification_email: ::std::option::Option<::std::string::String>,
    pub(crate) public_sharing_enabled: ::std::option::Option<bool>,
    pub(crate) termination_protection_enabled: ::std::option::Option<bool>,
}
impl AccountSettingsBuilder {
    /// <p>The "account name" you provided for the Amazon QuickSight subscription in your Amazon Web Services account. You create this name when you sign up for Amazon QuickSight. It is unique in all of Amazon Web Services and it appears only when users sign in.</p>
    pub fn account_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The "account name" you provided for the Amazon QuickSight subscription in your Amazon Web Services account. You create this name when you sign up for Amazon QuickSight. It is unique in all of Amazon Web Services and it appears only when users sign in.</p>
    pub fn set_account_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_name = input;
        self
    }
    /// <p>The "account name" you provided for the Amazon QuickSight subscription in your Amazon Web Services account. You create this name when you sign up for Amazon QuickSight. It is unique in all of Amazon Web Services and it appears only when users sign in.</p>
    pub fn get_account_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_name
    }
    /// <p>The edition of Amazon QuickSight that you're currently subscribed to: Enterprise edition or Standard edition.</p>
    pub fn edition(mut self, input: crate::types::Edition) -> Self {
        self.edition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The edition of Amazon QuickSight that you're currently subscribed to: Enterprise edition or Standard edition.</p>
    pub fn set_edition(mut self, input: ::std::option::Option<crate::types::Edition>) -> Self {
        self.edition = input;
        self
    }
    /// <p>The edition of Amazon QuickSight that you're currently subscribed to: Enterprise edition or Standard edition.</p>
    pub fn get_edition(&self) -> &::std::option::Option<crate::types::Edition> {
        &self.edition
    }
    /// <p>The default Amazon QuickSight namespace for your Amazon Web Services account.</p>
    pub fn default_namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The default Amazon QuickSight namespace for your Amazon Web Services account.</p>
    pub fn set_default_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_namespace = input;
        self
    }
    /// <p>The default Amazon QuickSight namespace for your Amazon Web Services account.</p>
    pub fn get_default_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_namespace
    }
    /// <p>The main notification email for your Amazon QuickSight subscription.</p>
    pub fn notification_email(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notification_email = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The main notification email for your Amazon QuickSight subscription.</p>
    pub fn set_notification_email(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notification_email = input;
        self
    }
    /// <p>The main notification email for your Amazon QuickSight subscription.</p>
    pub fn get_notification_email(&self) -> &::std::option::Option<::std::string::String> {
        &self.notification_email
    }
    /// <p>A Boolean value that indicates whether public sharing is turned on for an Amazon QuickSight account. For more information about turning on public sharing, see <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_UpdatePublicSharingSettings.html">UpdatePublicSharingSettings</a>.</p>
    pub fn public_sharing_enabled(mut self, input: bool) -> Self {
        self.public_sharing_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value that indicates whether public sharing is turned on for an Amazon QuickSight account. For more information about turning on public sharing, see <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_UpdatePublicSharingSettings.html">UpdatePublicSharingSettings</a>.</p>
    pub fn set_public_sharing_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.public_sharing_enabled = input;
        self
    }
    /// <p>A Boolean value that indicates whether public sharing is turned on for an Amazon QuickSight account. For more information about turning on public sharing, see <a href="https://docs.aws.amazon.com/quicksight/latest/APIReference/API_UpdatePublicSharingSettings.html">UpdatePublicSharingSettings</a>.</p>
    pub fn get_public_sharing_enabled(&self) -> &::std::option::Option<bool> {
        &self.public_sharing_enabled
    }
    /// <p>A boolean value that determines whether or not an Amazon QuickSight account can be deleted. A <code>True</code> value doesn't allow the account to be deleted and results in an error message if a user tries to make a <code>DeleteAccountSubsctiption</code> request. A <code>False</code> value will allow the ccount to be deleted.</p>
    pub fn termination_protection_enabled(mut self, input: bool) -> Self {
        self.termination_protection_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>A boolean value that determines whether or not an Amazon QuickSight account can be deleted. A <code>True</code> value doesn't allow the account to be deleted and results in an error message if a user tries to make a <code>DeleteAccountSubsctiption</code> request. A <code>False</code> value will allow the ccount to be deleted.</p>
    pub fn set_termination_protection_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.termination_protection_enabled = input;
        self
    }
    /// <p>A boolean value that determines whether or not an Amazon QuickSight account can be deleted. A <code>True</code> value doesn't allow the account to be deleted and results in an error message if a user tries to make a <code>DeleteAccountSubsctiption</code> request. A <code>False</code> value will allow the ccount to be deleted.</p>
    pub fn get_termination_protection_enabled(&self) -> &::std::option::Option<bool> {
        &self.termination_protection_enabled
    }
    /// Consumes the builder and constructs a [`AccountSettings`](crate::types::AccountSettings).
    pub fn build(self) -> crate::types::AccountSettings {
        crate::types::AccountSettings {
            account_name: self.account_name,
            edition: self.edition,
            default_namespace: self.default_namespace,
            notification_email: self.notification_email,
            public_sharing_enabled: self.public_sharing_enabled.unwrap_or_default(),
            termination_protection_enabled: self.termination_protection_enabled.unwrap_or_default(),
        }
    }
}
