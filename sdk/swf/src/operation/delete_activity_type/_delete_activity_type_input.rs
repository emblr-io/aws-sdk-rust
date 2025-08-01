// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteActivityTypeInput {
    /// <p>The name of the domain in which the activity type is registered.</p>
    pub domain: ::std::option::Option<::std::string::String>,
    /// <p>The activity type to delete.</p>
    pub activity_type: ::std::option::Option<crate::types::ActivityType>,
}
impl DeleteActivityTypeInput {
    /// <p>The name of the domain in which the activity type is registered.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
    /// <p>The activity type to delete.</p>
    pub fn activity_type(&self) -> ::std::option::Option<&crate::types::ActivityType> {
        self.activity_type.as_ref()
    }
}
impl DeleteActivityTypeInput {
    /// Creates a new builder-style object to manufacture [`DeleteActivityTypeInput`](crate::operation::delete_activity_type::DeleteActivityTypeInput).
    pub fn builder() -> crate::operation::delete_activity_type::builders::DeleteActivityTypeInputBuilder {
        crate::operation::delete_activity_type::builders::DeleteActivityTypeInputBuilder::default()
    }
}

/// A builder for [`DeleteActivityTypeInput`](crate::operation::delete_activity_type::DeleteActivityTypeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteActivityTypeInputBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
    pub(crate) activity_type: ::std::option::Option<crate::types::ActivityType>,
}
impl DeleteActivityTypeInputBuilder {
    /// <p>The name of the domain in which the activity type is registered.</p>
    /// This field is required.
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain in which the activity type is registered.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The name of the domain in which the activity type is registered.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// <p>The activity type to delete.</p>
    /// This field is required.
    pub fn activity_type(mut self, input: crate::types::ActivityType) -> Self {
        self.activity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The activity type to delete.</p>
    pub fn set_activity_type(mut self, input: ::std::option::Option<crate::types::ActivityType>) -> Self {
        self.activity_type = input;
        self
    }
    /// <p>The activity type to delete.</p>
    pub fn get_activity_type(&self) -> &::std::option::Option<crate::types::ActivityType> {
        &self.activity_type
    }
    /// Consumes the builder and constructs a [`DeleteActivityTypeInput`](crate::operation::delete_activity_type::DeleteActivityTypeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_activity_type::DeleteActivityTypeInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_activity_type::DeleteActivityTypeInput {
            domain: self.domain,
            activity_type: self.activity_type,
        })
    }
}
