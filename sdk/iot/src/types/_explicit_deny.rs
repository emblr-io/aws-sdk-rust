// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information that explicitly denies authorization.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExplicitDeny {
    /// <p>The policies that denied the authorization.</p>
    pub policies: ::std::option::Option<::std::vec::Vec<crate::types::Policy>>,
}
impl ExplicitDeny {
    /// <p>The policies that denied the authorization.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.policies.is_none()`.
    pub fn policies(&self) -> &[crate::types::Policy] {
        self.policies.as_deref().unwrap_or_default()
    }
}
impl ExplicitDeny {
    /// Creates a new builder-style object to manufacture [`ExplicitDeny`](crate::types::ExplicitDeny).
    pub fn builder() -> crate::types::builders::ExplicitDenyBuilder {
        crate::types::builders::ExplicitDenyBuilder::default()
    }
}

/// A builder for [`ExplicitDeny`](crate::types::ExplicitDeny).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExplicitDenyBuilder {
    pub(crate) policies: ::std::option::Option<::std::vec::Vec<crate::types::Policy>>,
}
impl ExplicitDenyBuilder {
    /// Appends an item to `policies`.
    ///
    /// To override the contents of this collection use [`set_policies`](Self::set_policies).
    ///
    /// <p>The policies that denied the authorization.</p>
    pub fn policies(mut self, input: crate::types::Policy) -> Self {
        let mut v = self.policies.unwrap_or_default();
        v.push(input);
        self.policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>The policies that denied the authorization.</p>
    pub fn set_policies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Policy>>) -> Self {
        self.policies = input;
        self
    }
    /// <p>The policies that denied the authorization.</p>
    pub fn get_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Policy>> {
        &self.policies
    }
    /// Consumes the builder and constructs a [`ExplicitDeny`](crate::types::ExplicitDeny).
    pub fn build(self) -> crate::types::ExplicitDeny {
        crate::types::ExplicitDeny { policies: self.policies }
    }
}
