// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an IAM instance profile.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateIamInstanceProfileSpecification {
    /// <p>The Amazon Resource Name (ARN) of the instance profile.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the instance profile.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl LaunchTemplateIamInstanceProfileSpecification {
    /// <p>The Amazon Resource Name (ARN) of the instance profile.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the instance profile.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl LaunchTemplateIamInstanceProfileSpecification {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateIamInstanceProfileSpecification`](crate::types::LaunchTemplateIamInstanceProfileSpecification).
    pub fn builder() -> crate::types::builders::LaunchTemplateIamInstanceProfileSpecificationBuilder {
        crate::types::builders::LaunchTemplateIamInstanceProfileSpecificationBuilder::default()
    }
}

/// A builder for [`LaunchTemplateIamInstanceProfileSpecification`](crate::types::LaunchTemplateIamInstanceProfileSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateIamInstanceProfileSpecificationBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl LaunchTemplateIamInstanceProfileSpecificationBuilder {
    /// <p>The Amazon Resource Name (ARN) of the instance profile.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the instance profile.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the instance profile.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the instance profile.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the instance profile.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the instance profile.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`LaunchTemplateIamInstanceProfileSpecification`](crate::types::LaunchTemplateIamInstanceProfileSpecification).
    pub fn build(self) -> crate::types::LaunchTemplateIamInstanceProfileSpecification {
        crate::types::LaunchTemplateIamInstanceProfileSpecification {
            arn: self.arn,
            name: self.name,
        }
    }
}
