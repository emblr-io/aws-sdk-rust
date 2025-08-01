// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summarizes all DDoS attacks for a specified time period.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttackSummary {
    /// <p>The unique identifier (ID) of the attack.</p>
    pub attack_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN (Amazon Resource Name) of the resource that was attacked.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The start time of the attack, in Unix time in seconds.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end time of the attack, in Unix time in seconds.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The list of attacks for a specified time period.</p>
    pub attack_vectors: ::std::option::Option<::std::vec::Vec<crate::types::AttackVectorDescription>>,
}
impl AttackSummary {
    /// <p>The unique identifier (ID) of the attack.</p>
    pub fn attack_id(&self) -> ::std::option::Option<&str> {
        self.attack_id.as_deref()
    }
    /// <p>The ARN (Amazon Resource Name) of the resource that was attacked.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The start time of the attack, in Unix time in seconds.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The end time of the attack, in Unix time in seconds.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The list of attacks for a specified time period.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attack_vectors.is_none()`.
    pub fn attack_vectors(&self) -> &[crate::types::AttackVectorDescription] {
        self.attack_vectors.as_deref().unwrap_or_default()
    }
}
impl AttackSummary {
    /// Creates a new builder-style object to manufacture [`AttackSummary`](crate::types::AttackSummary).
    pub fn builder() -> crate::types::builders::AttackSummaryBuilder {
        crate::types::builders::AttackSummaryBuilder::default()
    }
}

/// A builder for [`AttackSummary`](crate::types::AttackSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttackSummaryBuilder {
    pub(crate) attack_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) attack_vectors: ::std::option::Option<::std::vec::Vec<crate::types::AttackVectorDescription>>,
}
impl AttackSummaryBuilder {
    /// <p>The unique identifier (ID) of the attack.</p>
    pub fn attack_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attack_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier (ID) of the attack.</p>
    pub fn set_attack_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attack_id = input;
        self
    }
    /// <p>The unique identifier (ID) of the attack.</p>
    pub fn get_attack_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.attack_id
    }
    /// <p>The ARN (Amazon Resource Name) of the resource that was attacked.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN (Amazon Resource Name) of the resource that was attacked.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN (Amazon Resource Name) of the resource that was attacked.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The start time of the attack, in Unix time in seconds.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start time of the attack, in Unix time in seconds.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start time of the attack, in Unix time in seconds.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The end time of the attack, in Unix time in seconds.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end time of the attack, in Unix time in seconds.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end time of the attack, in Unix time in seconds.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Appends an item to `attack_vectors`.
    ///
    /// To override the contents of this collection use [`set_attack_vectors`](Self::set_attack_vectors).
    ///
    /// <p>The list of attacks for a specified time period.</p>
    pub fn attack_vectors(mut self, input: crate::types::AttackVectorDescription) -> Self {
        let mut v = self.attack_vectors.unwrap_or_default();
        v.push(input);
        self.attack_vectors = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of attacks for a specified time period.</p>
    pub fn set_attack_vectors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AttackVectorDescription>>) -> Self {
        self.attack_vectors = input;
        self
    }
    /// <p>The list of attacks for a specified time period.</p>
    pub fn get_attack_vectors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AttackVectorDescription>> {
        &self.attack_vectors
    }
    /// Consumes the builder and constructs a [`AttackSummary`](crate::types::AttackSummary).
    pub fn build(self) -> crate::types::AttackSummary {
        crate::types::AttackSummary {
            attack_id: self.attack_id,
            resource_arn: self.resource_arn,
            start_time: self.start_time,
            end_time: self.end_time,
            attack_vectors: self.attack_vectors,
        }
    }
}
