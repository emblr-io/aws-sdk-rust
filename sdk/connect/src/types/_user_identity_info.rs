// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the identity of a user.</p><note>
/// <p>For Amazon Connect instances that are created with the <code>EXISTING_DIRECTORY</code> identity management type, <code>FirstName</code>, <code>LastName</code>, and <code>Email</code> cannot be updated from within Amazon Connect because they are managed by the directory.</p>
/// </note> <important>
/// <p>The <code>FirstName</code> and <code>LastName</code> length constraints below apply only to instances using SAML for identity management. If you are using Amazon Connect for identity management, the length constraints are 1-255 for <code>FirstName</code>, and 1-256 for <code>LastName</code>.</p>
/// </important>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UserIdentityInfo {
    /// <p>The first name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub first_name: ::std::option::Option<::std::string::String>,
    /// <p>The last name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub last_name: ::std::option::Option<::std::string::String>,
    /// <p>The email address. If you are using SAML for identity management and include this parameter, an error is returned.</p>
    pub email: ::std::option::Option<::std::string::String>,
    /// <p>The user's secondary email address. If you provide a secondary email, the user receives email notifications - other than password reset notifications - to this email address instead of to their primary email address.</p>
    /// <p>Pattern: <code>(?=^.{0,265}$)\[a-zA-Z0-9._%+-\]+@\[a-zA-Z0-9.-\]+\.\[a-zA-Z\]{2,63}</code></p>
    pub secondary_email: ::std::option::Option<::std::string::String>,
    /// <p>The user's mobile number.</p>
    pub mobile: ::std::option::Option<::std::string::String>,
}
impl UserIdentityInfo {
    /// <p>The first name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub fn first_name(&self) -> ::std::option::Option<&str> {
        self.first_name.as_deref()
    }
    /// <p>The last name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub fn last_name(&self) -> ::std::option::Option<&str> {
        self.last_name.as_deref()
    }
    /// <p>The email address. If you are using SAML for identity management and include this parameter, an error is returned.</p>
    pub fn email(&self) -> ::std::option::Option<&str> {
        self.email.as_deref()
    }
    /// <p>The user's secondary email address. If you provide a secondary email, the user receives email notifications - other than password reset notifications - to this email address instead of to their primary email address.</p>
    /// <p>Pattern: <code>(?=^.{0,265}$)\[a-zA-Z0-9._%+-\]+@\[a-zA-Z0-9.-\]+\.\[a-zA-Z\]{2,63}</code></p>
    pub fn secondary_email(&self) -> ::std::option::Option<&str> {
        self.secondary_email.as_deref()
    }
    /// <p>The user's mobile number.</p>
    pub fn mobile(&self) -> ::std::option::Option<&str> {
        self.mobile.as_deref()
    }
}
impl ::std::fmt::Debug for UserIdentityInfo {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UserIdentityInfo");
        formatter.field("first_name", &"*** Sensitive Data Redacted ***");
        formatter.field("last_name", &"*** Sensitive Data Redacted ***");
        formatter.field("email", &"*** Sensitive Data Redacted ***");
        formatter.field("secondary_email", &"*** Sensitive Data Redacted ***");
        formatter.field("mobile", &self.mobile);
        formatter.finish()
    }
}
impl UserIdentityInfo {
    /// Creates a new builder-style object to manufacture [`UserIdentityInfo`](crate::types::UserIdentityInfo).
    pub fn builder() -> crate::types::builders::UserIdentityInfoBuilder {
        crate::types::builders::UserIdentityInfoBuilder::default()
    }
}

/// A builder for [`UserIdentityInfo`](crate::types::UserIdentityInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UserIdentityInfoBuilder {
    pub(crate) first_name: ::std::option::Option<::std::string::String>,
    pub(crate) last_name: ::std::option::Option<::std::string::String>,
    pub(crate) email: ::std::option::Option<::std::string::String>,
    pub(crate) secondary_email: ::std::option::Option<::std::string::String>,
    pub(crate) mobile: ::std::option::Option<::std::string::String>,
}
impl UserIdentityInfoBuilder {
    /// <p>The first name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub fn first_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.first_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The first name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub fn set_first_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.first_name = input;
        self
    }
    /// <p>The first name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub fn get_first_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.first_name
    }
    /// <p>The last name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub fn last_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The last name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub fn set_last_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_name = input;
        self
    }
    /// <p>The last name. This is required if you are using Amazon Connect or SAML for identity management. Inputs must be in Unicode Normalization Form C (NFC). Text containing characters in a non-NFC form (for example, decomposed characters or combining marks) are not accepted.</p>
    pub fn get_last_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_name
    }
    /// <p>The email address. If you are using SAML for identity management and include this parameter, an error is returned.</p>
    pub fn email(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address. If you are using SAML for identity management and include this parameter, an error is returned.</p>
    pub fn set_email(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email = input;
        self
    }
    /// <p>The email address. If you are using SAML for identity management and include this parameter, an error is returned.</p>
    pub fn get_email(&self) -> &::std::option::Option<::std::string::String> {
        &self.email
    }
    /// <p>The user's secondary email address. If you provide a secondary email, the user receives email notifications - other than password reset notifications - to this email address instead of to their primary email address.</p>
    /// <p>Pattern: <code>(?=^.{0,265}$)\[a-zA-Z0-9._%+-\]+@\[a-zA-Z0-9.-\]+\.\[a-zA-Z\]{2,63}</code></p>
    pub fn secondary_email(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secondary_email = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user's secondary email address. If you provide a secondary email, the user receives email notifications - other than password reset notifications - to this email address instead of to their primary email address.</p>
    /// <p>Pattern: <code>(?=^.{0,265}$)\[a-zA-Z0-9._%+-\]+@\[a-zA-Z0-9.-\]+\.\[a-zA-Z\]{2,63}</code></p>
    pub fn set_secondary_email(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secondary_email = input;
        self
    }
    /// <p>The user's secondary email address. If you provide a secondary email, the user receives email notifications - other than password reset notifications - to this email address instead of to their primary email address.</p>
    /// <p>Pattern: <code>(?=^.{0,265}$)\[a-zA-Z0-9._%+-\]+@\[a-zA-Z0-9.-\]+\.\[a-zA-Z\]{2,63}</code></p>
    pub fn get_secondary_email(&self) -> &::std::option::Option<::std::string::String> {
        &self.secondary_email
    }
    /// <p>The user's mobile number.</p>
    pub fn mobile(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mobile = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user's mobile number.</p>
    pub fn set_mobile(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mobile = input;
        self
    }
    /// <p>The user's mobile number.</p>
    pub fn get_mobile(&self) -> &::std::option::Option<::std::string::String> {
        &self.mobile
    }
    /// Consumes the builder and constructs a [`UserIdentityInfo`](crate::types::UserIdentityInfo).
    pub fn build(self) -> crate::types::UserIdentityInfo {
        crate::types::UserIdentityInfo {
            first_name: self.first_name,
            last_name: self.last_name,
            email: self.email,
            secondary_email: self.secondary_email,
            mobile: self.mobile,
        }
    }
}
impl ::std::fmt::Debug for UserIdentityInfoBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UserIdentityInfoBuilder");
        formatter.field("first_name", &"*** Sensitive Data Redacted ***");
        formatter.field("last_name", &"*** Sensitive Data Redacted ***");
        formatter.field("email", &"*** Sensitive Data Redacted ***");
        formatter.field("secondary_email", &"*** Sensitive Data Redacted ***");
        formatter.field("mobile", &self.mobile);
        formatter.finish()
    }
}
