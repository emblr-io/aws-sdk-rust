// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterTargetsInput {
    /// <p>The Amazon Resource Name (ARN) of the target group.</p>
    pub target_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The targets.</p>
    pub targets: ::std::option::Option<::std::vec::Vec<crate::types::TargetDescription>>,
}
impl RegisterTargetsInput {
    /// <p>The Amazon Resource Name (ARN) of the target group.</p>
    pub fn target_group_arn(&self) -> ::std::option::Option<&str> {
        self.target_group_arn.as_deref()
    }
    /// <p>The targets.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.targets.is_none()`.
    pub fn targets(&self) -> &[crate::types::TargetDescription] {
        self.targets.as_deref().unwrap_or_default()
    }
}
impl RegisterTargetsInput {
    /// Creates a new builder-style object to manufacture [`RegisterTargetsInput`](crate::operation::register_targets::RegisterTargetsInput).
    pub fn builder() -> crate::operation::register_targets::builders::RegisterTargetsInputBuilder {
        crate::operation::register_targets::builders::RegisterTargetsInputBuilder::default()
    }
}

/// A builder for [`RegisterTargetsInput`](crate::operation::register_targets::RegisterTargetsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterTargetsInputBuilder {
    pub(crate) target_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) targets: ::std::option::Option<::std::vec::Vec<crate::types::TargetDescription>>,
}
impl RegisterTargetsInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the target group.</p>
    /// This field is required.
    pub fn target_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target group.</p>
    pub fn set_target_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target group.</p>
    pub fn get_target_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_group_arn
    }
    /// Appends an item to `targets`.
    ///
    /// To override the contents of this collection use [`set_targets`](Self::set_targets).
    ///
    /// <p>The targets.</p>
    pub fn targets(mut self, input: crate::types::TargetDescription) -> Self {
        let mut v = self.targets.unwrap_or_default();
        v.push(input);
        self.targets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The targets.</p>
    pub fn set_targets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TargetDescription>>) -> Self {
        self.targets = input;
        self
    }
    /// <p>The targets.</p>
    pub fn get_targets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TargetDescription>> {
        &self.targets
    }
    /// Consumes the builder and constructs a [`RegisterTargetsInput`](crate::operation::register_targets::RegisterTargetsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::register_targets::RegisterTargetsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::register_targets::RegisterTargetsInput {
            target_group_arn: self.target_group_arn,
            targets: self.targets,
        })
    }
}
