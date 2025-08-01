// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The policy for allowed types of authentication in a user pool. To activate this setting, your user pool must be in the <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/feature-plans-features-essentials.html"> Essentials tier</a> or higher.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SignInPolicyType {
    /// <p>The sign-in methods that a user pool supports as the first factor. You can permit users to start authentication with a standard username and password, or with other one-time password and hardware factors.</p>
    pub allowed_first_auth_factors: ::std::option::Option<::std::vec::Vec<crate::types::AuthFactorType>>,
}
impl SignInPolicyType {
    /// <p>The sign-in methods that a user pool supports as the first factor. You can permit users to start authentication with a standard username and password, or with other one-time password and hardware factors.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.allowed_first_auth_factors.is_none()`.
    pub fn allowed_first_auth_factors(&self) -> &[crate::types::AuthFactorType] {
        self.allowed_first_auth_factors.as_deref().unwrap_or_default()
    }
}
impl SignInPolicyType {
    /// Creates a new builder-style object to manufacture [`SignInPolicyType`](crate::types::SignInPolicyType).
    pub fn builder() -> crate::types::builders::SignInPolicyTypeBuilder {
        crate::types::builders::SignInPolicyTypeBuilder::default()
    }
}

/// A builder for [`SignInPolicyType`](crate::types::SignInPolicyType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SignInPolicyTypeBuilder {
    pub(crate) allowed_first_auth_factors: ::std::option::Option<::std::vec::Vec<crate::types::AuthFactorType>>,
}
impl SignInPolicyTypeBuilder {
    /// Appends an item to `allowed_first_auth_factors`.
    ///
    /// To override the contents of this collection use [`set_allowed_first_auth_factors`](Self::set_allowed_first_auth_factors).
    ///
    /// <p>The sign-in methods that a user pool supports as the first factor. You can permit users to start authentication with a standard username and password, or with other one-time password and hardware factors.</p>
    pub fn allowed_first_auth_factors(mut self, input: crate::types::AuthFactorType) -> Self {
        let mut v = self.allowed_first_auth_factors.unwrap_or_default();
        v.push(input);
        self.allowed_first_auth_factors = ::std::option::Option::Some(v);
        self
    }
    /// <p>The sign-in methods that a user pool supports as the first factor. You can permit users to start authentication with a standard username and password, or with other one-time password and hardware factors.</p>
    pub fn set_allowed_first_auth_factors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AuthFactorType>>) -> Self {
        self.allowed_first_auth_factors = input;
        self
    }
    /// <p>The sign-in methods that a user pool supports as the first factor. You can permit users to start authentication with a standard username and password, or with other one-time password and hardware factors.</p>
    pub fn get_allowed_first_auth_factors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AuthFactorType>> {
        &self.allowed_first_auth_factors
    }
    /// Consumes the builder and constructs a [`SignInPolicyType`](crate::types::SignInPolicyType).
    pub fn build(self) -> crate::types::SignInPolicyType {
        crate::types::SignInPolicyType {
            allowed_first_auth_factors: self.allowed_first_auth_factors,
        }
    }
}
