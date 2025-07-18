// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a security profile and the target associated with it.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SecurityProfileTargetMapping {
    /// <p>Information that identifies the security profile.</p>
    pub security_profile_identifier: ::std::option::Option<crate::types::SecurityProfileIdentifier>,
    /// <p>Information about the target (thing group) associated with the security profile.</p>
    pub target: ::std::option::Option<crate::types::SecurityProfileTarget>,
}
impl SecurityProfileTargetMapping {
    /// <p>Information that identifies the security profile.</p>
    pub fn security_profile_identifier(&self) -> ::std::option::Option<&crate::types::SecurityProfileIdentifier> {
        self.security_profile_identifier.as_ref()
    }
    /// <p>Information about the target (thing group) associated with the security profile.</p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::SecurityProfileTarget> {
        self.target.as_ref()
    }
}
impl SecurityProfileTargetMapping {
    /// Creates a new builder-style object to manufacture [`SecurityProfileTargetMapping`](crate::types::SecurityProfileTargetMapping).
    pub fn builder() -> crate::types::builders::SecurityProfileTargetMappingBuilder {
        crate::types::builders::SecurityProfileTargetMappingBuilder::default()
    }
}

/// A builder for [`SecurityProfileTargetMapping`](crate::types::SecurityProfileTargetMapping).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SecurityProfileTargetMappingBuilder {
    pub(crate) security_profile_identifier: ::std::option::Option<crate::types::SecurityProfileIdentifier>,
    pub(crate) target: ::std::option::Option<crate::types::SecurityProfileTarget>,
}
impl SecurityProfileTargetMappingBuilder {
    /// <p>Information that identifies the security profile.</p>
    pub fn security_profile_identifier(mut self, input: crate::types::SecurityProfileIdentifier) -> Self {
        self.security_profile_identifier = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information that identifies the security profile.</p>
    pub fn set_security_profile_identifier(mut self, input: ::std::option::Option<crate::types::SecurityProfileIdentifier>) -> Self {
        self.security_profile_identifier = input;
        self
    }
    /// <p>Information that identifies the security profile.</p>
    pub fn get_security_profile_identifier(&self) -> &::std::option::Option<crate::types::SecurityProfileIdentifier> {
        &self.security_profile_identifier
    }
    /// <p>Information about the target (thing group) associated with the security profile.</p>
    pub fn target(mut self, input: crate::types::SecurityProfileTarget) -> Self {
        self.target = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the target (thing group) associated with the security profile.</p>
    pub fn set_target(mut self, input: ::std::option::Option<crate::types::SecurityProfileTarget>) -> Self {
        self.target = input;
        self
    }
    /// <p>Information about the target (thing group) associated with the security profile.</p>
    pub fn get_target(&self) -> &::std::option::Option<crate::types::SecurityProfileTarget> {
        &self.target
    }
    /// Consumes the builder and constructs a [`SecurityProfileTargetMapping`](crate::types::SecurityProfileTargetMapping).
    pub fn build(self) -> crate::types::SecurityProfileTargetMapping {
        crate::types::SecurityProfileTargetMapping {
            security_profile_identifier: self.security_profile_identifier,
            target: self.target,
        }
    }
}
