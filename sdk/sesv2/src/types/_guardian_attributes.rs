// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object containing additional settings for your VDM configuration as applicable to the Guardian.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GuardianAttributes {
    /// <p>Specifies the status of your VDM optimized shared delivery. Can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – Amazon SES enables optimized shared delivery for your account.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – Amazon SES disables optimized shared delivery for your account.</p></li>
    /// </ul>
    pub optimized_shared_delivery: ::std::option::Option<crate::types::FeatureStatus>,
}
impl GuardianAttributes {
    /// <p>Specifies the status of your VDM optimized shared delivery. Can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – Amazon SES enables optimized shared delivery for your account.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – Amazon SES disables optimized shared delivery for your account.</p></li>
    /// </ul>
    pub fn optimized_shared_delivery(&self) -> ::std::option::Option<&crate::types::FeatureStatus> {
        self.optimized_shared_delivery.as_ref()
    }
}
impl GuardianAttributes {
    /// Creates a new builder-style object to manufacture [`GuardianAttributes`](crate::types::GuardianAttributes).
    pub fn builder() -> crate::types::builders::GuardianAttributesBuilder {
        crate::types::builders::GuardianAttributesBuilder::default()
    }
}

/// A builder for [`GuardianAttributes`](crate::types::GuardianAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GuardianAttributesBuilder {
    pub(crate) optimized_shared_delivery: ::std::option::Option<crate::types::FeatureStatus>,
}
impl GuardianAttributesBuilder {
    /// <p>Specifies the status of your VDM optimized shared delivery. Can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – Amazon SES enables optimized shared delivery for your account.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – Amazon SES disables optimized shared delivery for your account.</p></li>
    /// </ul>
    pub fn optimized_shared_delivery(mut self, input: crate::types::FeatureStatus) -> Self {
        self.optimized_shared_delivery = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the status of your VDM optimized shared delivery. Can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – Amazon SES enables optimized shared delivery for your account.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – Amazon SES disables optimized shared delivery for your account.</p></li>
    /// </ul>
    pub fn set_optimized_shared_delivery(mut self, input: ::std::option::Option<crate::types::FeatureStatus>) -> Self {
        self.optimized_shared_delivery = input;
        self
    }
    /// <p>Specifies the status of your VDM optimized shared delivery. Can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – Amazon SES enables optimized shared delivery for your account.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – Amazon SES disables optimized shared delivery for your account.</p></li>
    /// </ul>
    pub fn get_optimized_shared_delivery(&self) -> &::std::option::Option<crate::types::FeatureStatus> {
        &self.optimized_shared_delivery
    }
    /// Consumes the builder and constructs a [`GuardianAttributes`](crate::types::GuardianAttributes).
    pub fn build(self) -> crate::types::GuardianAttributes {
        crate::types::GuardianAttributes {
            optimized_shared_delivery: self.optimized_shared_delivery,
        }
    }
}
