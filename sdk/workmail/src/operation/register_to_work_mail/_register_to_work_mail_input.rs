// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterToWorkMailInput {
    /// <p>The identifier for the organization under which the user, group, or resource exists.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the user, group, or resource to be updated.</p>
    /// <p>The identifier can accept <i>UserId, ResourceId, or GroupId</i>, or <i>Username, Resourcename, or Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Entity ID: 12345678-1234-1234-1234-123456789012, r-0123456789a0123456789b0123456789, or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Entity name: entity</p></li>
    /// </ul>
    pub entity_id: ::std::option::Option<::std::string::String>,
    /// <p>The email for the user, group, or resource to be updated.</p>
    pub email: ::std::option::Option<::std::string::String>,
}
impl RegisterToWorkMailInput {
    /// <p>The identifier for the organization under which the user, group, or resource exists.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The identifier for the user, group, or resource to be updated.</p>
    /// <p>The identifier can accept <i>UserId, ResourceId, or GroupId</i>, or <i>Username, Resourcename, or Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Entity ID: 12345678-1234-1234-1234-123456789012, r-0123456789a0123456789b0123456789, or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Entity name: entity</p></li>
    /// </ul>
    pub fn entity_id(&self) -> ::std::option::Option<&str> {
        self.entity_id.as_deref()
    }
    /// <p>The email for the user, group, or resource to be updated.</p>
    pub fn email(&self) -> ::std::option::Option<&str> {
        self.email.as_deref()
    }
}
impl RegisterToWorkMailInput {
    /// Creates a new builder-style object to manufacture [`RegisterToWorkMailInput`](crate::operation::register_to_work_mail::RegisterToWorkMailInput).
    pub fn builder() -> crate::operation::register_to_work_mail::builders::RegisterToWorkMailInputBuilder {
        crate::operation::register_to_work_mail::builders::RegisterToWorkMailInputBuilder::default()
    }
}

/// A builder for [`RegisterToWorkMailInput`](crate::operation::register_to_work_mail::RegisterToWorkMailInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterToWorkMailInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) entity_id: ::std::option::Option<::std::string::String>,
    pub(crate) email: ::std::option::Option<::std::string::String>,
}
impl RegisterToWorkMailInputBuilder {
    /// <p>The identifier for the organization under which the user, group, or resource exists.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the organization under which the user, group, or resource exists.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The identifier for the organization under which the user, group, or resource exists.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The identifier for the user, group, or resource to be updated.</p>
    /// <p>The identifier can accept <i>UserId, ResourceId, or GroupId</i>, or <i>Username, Resourcename, or Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Entity ID: 12345678-1234-1234-1234-123456789012, r-0123456789a0123456789b0123456789, or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Entity name: entity</p></li>
    /// </ul>
    /// This field is required.
    pub fn entity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the user, group, or resource to be updated.</p>
    /// <p>The identifier can accept <i>UserId, ResourceId, or GroupId</i>, or <i>Username, Resourcename, or Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Entity ID: 12345678-1234-1234-1234-123456789012, r-0123456789a0123456789b0123456789, or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Entity name: entity</p></li>
    /// </ul>
    pub fn set_entity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entity_id = input;
        self
    }
    /// <p>The identifier for the user, group, or resource to be updated.</p>
    /// <p>The identifier can accept <i>UserId, ResourceId, or GroupId</i>, or <i>Username, Resourcename, or Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Entity ID: 12345678-1234-1234-1234-123456789012, r-0123456789a0123456789b0123456789, or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Entity name: entity</p></li>
    /// </ul>
    pub fn get_entity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.entity_id
    }
    /// <p>The email for the user, group, or resource to be updated.</p>
    /// This field is required.
    pub fn email(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email for the user, group, or resource to be updated.</p>
    pub fn set_email(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email = input;
        self
    }
    /// <p>The email for the user, group, or resource to be updated.</p>
    pub fn get_email(&self) -> &::std::option::Option<::std::string::String> {
        &self.email
    }
    /// Consumes the builder and constructs a [`RegisterToWorkMailInput`](crate::operation::register_to_work_mail::RegisterToWorkMailInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::register_to_work_mail::RegisterToWorkMailInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::register_to_work_mail::RegisterToWorkMailInput {
            organization_id: self.organization_id,
            entity_id: self.entity_id,
            email: self.email,
        })
    }
}
