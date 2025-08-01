// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that describes the options for the access portal associated with an application that can be updated.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateApplicationPortalOptions {
    /// <p>A structure that describes the sign-in options for an application portal.</p>
    pub sign_in_options: ::std::option::Option<crate::types::SignInOptions>,
}
impl UpdateApplicationPortalOptions {
    /// <p>A structure that describes the sign-in options for an application portal.</p>
    pub fn sign_in_options(&self) -> ::std::option::Option<&crate::types::SignInOptions> {
        self.sign_in_options.as_ref()
    }
}
impl UpdateApplicationPortalOptions {
    /// Creates a new builder-style object to manufacture [`UpdateApplicationPortalOptions`](crate::types::UpdateApplicationPortalOptions).
    pub fn builder() -> crate::types::builders::UpdateApplicationPortalOptionsBuilder {
        crate::types::builders::UpdateApplicationPortalOptionsBuilder::default()
    }
}

/// A builder for [`UpdateApplicationPortalOptions`](crate::types::UpdateApplicationPortalOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateApplicationPortalOptionsBuilder {
    pub(crate) sign_in_options: ::std::option::Option<crate::types::SignInOptions>,
}
impl UpdateApplicationPortalOptionsBuilder {
    /// <p>A structure that describes the sign-in options for an application portal.</p>
    pub fn sign_in_options(mut self, input: crate::types::SignInOptions) -> Self {
        self.sign_in_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that describes the sign-in options for an application portal.</p>
    pub fn set_sign_in_options(mut self, input: ::std::option::Option<crate::types::SignInOptions>) -> Self {
        self.sign_in_options = input;
        self
    }
    /// <p>A structure that describes the sign-in options for an application portal.</p>
    pub fn get_sign_in_options(&self) -> &::std::option::Option<crate::types::SignInOptions> {
        &self.sign_in_options
    }
    /// Consumes the builder and constructs a [`UpdateApplicationPortalOptions`](crate::types::UpdateApplicationPortalOptions).
    pub fn build(self) -> crate::types::UpdateApplicationPortalOptions {
        crate::types::UpdateApplicationPortalOptions {
            sign_in_options: self.sign_in_options,
        }
    }
}
