// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies configurations for one or more training jobs that SageMaker runs to test the algorithm.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AlgorithmValidationSpecification {
    /// <p>The IAM roles that SageMaker uses to run the training jobs.</p>
    pub validation_role: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>AlgorithmValidationProfile</code> objects, each of which specifies a training job and batch transform job that SageMaker runs to validate your algorithm.</p>
    pub validation_profiles: ::std::option::Option<::std::vec::Vec<crate::types::AlgorithmValidationProfile>>,
}
impl AlgorithmValidationSpecification {
    /// <p>The IAM roles that SageMaker uses to run the training jobs.</p>
    pub fn validation_role(&self) -> ::std::option::Option<&str> {
        self.validation_role.as_deref()
    }
    /// <p>An array of <code>AlgorithmValidationProfile</code> objects, each of which specifies a training job and batch transform job that SageMaker runs to validate your algorithm.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.validation_profiles.is_none()`.
    pub fn validation_profiles(&self) -> &[crate::types::AlgorithmValidationProfile] {
        self.validation_profiles.as_deref().unwrap_or_default()
    }
}
impl AlgorithmValidationSpecification {
    /// Creates a new builder-style object to manufacture [`AlgorithmValidationSpecification`](crate::types::AlgorithmValidationSpecification).
    pub fn builder() -> crate::types::builders::AlgorithmValidationSpecificationBuilder {
        crate::types::builders::AlgorithmValidationSpecificationBuilder::default()
    }
}

/// A builder for [`AlgorithmValidationSpecification`](crate::types::AlgorithmValidationSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AlgorithmValidationSpecificationBuilder {
    pub(crate) validation_role: ::std::option::Option<::std::string::String>,
    pub(crate) validation_profiles: ::std::option::Option<::std::vec::Vec<crate::types::AlgorithmValidationProfile>>,
}
impl AlgorithmValidationSpecificationBuilder {
    /// <p>The IAM roles that SageMaker uses to run the training jobs.</p>
    /// This field is required.
    pub fn validation_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.validation_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM roles that SageMaker uses to run the training jobs.</p>
    pub fn set_validation_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.validation_role = input;
        self
    }
    /// <p>The IAM roles that SageMaker uses to run the training jobs.</p>
    pub fn get_validation_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.validation_role
    }
    /// Appends an item to `validation_profiles`.
    ///
    /// To override the contents of this collection use [`set_validation_profiles`](Self::set_validation_profiles).
    ///
    /// <p>An array of <code>AlgorithmValidationProfile</code> objects, each of which specifies a training job and batch transform job that SageMaker runs to validate your algorithm.</p>
    pub fn validation_profiles(mut self, input: crate::types::AlgorithmValidationProfile) -> Self {
        let mut v = self.validation_profiles.unwrap_or_default();
        v.push(input);
        self.validation_profiles = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>AlgorithmValidationProfile</code> objects, each of which specifies a training job and batch transform job that SageMaker runs to validate your algorithm.</p>
    pub fn set_validation_profiles(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AlgorithmValidationProfile>>) -> Self {
        self.validation_profiles = input;
        self
    }
    /// <p>An array of <code>AlgorithmValidationProfile</code> objects, each of which specifies a training job and batch transform job that SageMaker runs to validate your algorithm.</p>
    pub fn get_validation_profiles(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AlgorithmValidationProfile>> {
        &self.validation_profiles
    }
    /// Consumes the builder and constructs a [`AlgorithmValidationSpecification`](crate::types::AlgorithmValidationSpecification).
    pub fn build(self) -> crate::types::AlgorithmValidationSpecification {
        crate::types::AlgorithmValidationSpecification {
            validation_role: self.validation_role,
            validation_profiles: self.validation_profiles,
        }
    }
}
