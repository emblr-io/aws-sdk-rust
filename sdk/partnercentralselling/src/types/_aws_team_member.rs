// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents an Amazon Web Services team member for the engagement. This structure includes details such as name, email, and business title.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AwsTeamMember {
    /// <p>Provides the Amazon Web Services team member's email address.</p>
    pub email: ::std::option::Option<::std::string::String>,
    /// <p>Provides the Amazon Web Services team member's first name.</p>
    pub first_name: ::std::option::Option<::std::string::String>,
    /// <p>Provides the Amazon Web Services team member's last name.</p>
    pub last_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the Amazon Web Services team member's business title and indicates their organizational role.</p>
    pub business_title: ::std::option::Option<crate::types::AwsMemberBusinessTitle>,
}
impl AwsTeamMember {
    /// <p>Provides the Amazon Web Services team member's email address.</p>
    pub fn email(&self) -> ::std::option::Option<&str> {
        self.email.as_deref()
    }
    /// <p>Provides the Amazon Web Services team member's first name.</p>
    pub fn first_name(&self) -> ::std::option::Option<&str> {
        self.first_name.as_deref()
    }
    /// <p>Provides the Amazon Web Services team member's last name.</p>
    pub fn last_name(&self) -> ::std::option::Option<&str> {
        self.last_name.as_deref()
    }
    /// <p>Specifies the Amazon Web Services team member's business title and indicates their organizational role.</p>
    pub fn business_title(&self) -> ::std::option::Option<&crate::types::AwsMemberBusinessTitle> {
        self.business_title.as_ref()
    }
}
impl ::std::fmt::Debug for AwsTeamMember {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AwsTeamMember");
        formatter.field("email", &"*** Sensitive Data Redacted ***");
        formatter.field("first_name", &"*** Sensitive Data Redacted ***");
        formatter.field("last_name", &"*** Sensitive Data Redacted ***");
        formatter.field("business_title", &self.business_title);
        formatter.finish()
    }
}
impl AwsTeamMember {
    /// Creates a new builder-style object to manufacture [`AwsTeamMember`](crate::types::AwsTeamMember).
    pub fn builder() -> crate::types::builders::AwsTeamMemberBuilder {
        crate::types::builders::AwsTeamMemberBuilder::default()
    }
}

/// A builder for [`AwsTeamMember`](crate::types::AwsTeamMember).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AwsTeamMemberBuilder {
    pub(crate) email: ::std::option::Option<::std::string::String>,
    pub(crate) first_name: ::std::option::Option<::std::string::String>,
    pub(crate) last_name: ::std::option::Option<::std::string::String>,
    pub(crate) business_title: ::std::option::Option<crate::types::AwsMemberBusinessTitle>,
}
impl AwsTeamMemberBuilder {
    /// <p>Provides the Amazon Web Services team member's email address.</p>
    pub fn email(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the Amazon Web Services team member's email address.</p>
    pub fn set_email(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email = input;
        self
    }
    /// <p>Provides the Amazon Web Services team member's email address.</p>
    pub fn get_email(&self) -> &::std::option::Option<::std::string::String> {
        &self.email
    }
    /// <p>Provides the Amazon Web Services team member's first name.</p>
    pub fn first_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.first_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the Amazon Web Services team member's first name.</p>
    pub fn set_first_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.first_name = input;
        self
    }
    /// <p>Provides the Amazon Web Services team member's first name.</p>
    pub fn get_first_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.first_name
    }
    /// <p>Provides the Amazon Web Services team member's last name.</p>
    pub fn last_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the Amazon Web Services team member's last name.</p>
    pub fn set_last_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_name = input;
        self
    }
    /// <p>Provides the Amazon Web Services team member's last name.</p>
    pub fn get_last_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_name
    }
    /// <p>Specifies the Amazon Web Services team member's business title and indicates their organizational role.</p>
    pub fn business_title(mut self, input: crate::types::AwsMemberBusinessTitle) -> Self {
        self.business_title = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the Amazon Web Services team member's business title and indicates their organizational role.</p>
    pub fn set_business_title(mut self, input: ::std::option::Option<crate::types::AwsMemberBusinessTitle>) -> Self {
        self.business_title = input;
        self
    }
    /// <p>Specifies the Amazon Web Services team member's business title and indicates their organizational role.</p>
    pub fn get_business_title(&self) -> &::std::option::Option<crate::types::AwsMemberBusinessTitle> {
        &self.business_title
    }
    /// Consumes the builder and constructs a [`AwsTeamMember`](crate::types::AwsTeamMember).
    pub fn build(self) -> crate::types::AwsTeamMember {
        crate::types::AwsTeamMember {
            email: self.email,
            first_name: self.first_name,
            last_name: self.last_name,
            business_title: self.business_title,
        }
    }
}
impl ::std::fmt::Debug for AwsTeamMemberBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AwsTeamMemberBuilder");
        formatter.field("email", &"*** Sensitive Data Redacted ***");
        formatter.field("first_name", &"*** Sensitive Data Redacted ***");
        formatter.field("last_name", &"*** Sensitive Data Redacted ***");
        formatter.field("business_title", &self.business_title);
        formatter.finish()
    }
}
