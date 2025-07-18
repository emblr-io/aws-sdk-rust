// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregisterJobDefinitionInput {
    /// <p>The name and revision (<code>name:revision</code>) or full Amazon Resource Name (ARN) of the job definition to deregister.</p>
    pub job_definition: ::std::option::Option<::std::string::String>,
}
impl DeregisterJobDefinitionInput {
    /// <p>The name and revision (<code>name:revision</code>) or full Amazon Resource Name (ARN) of the job definition to deregister.</p>
    pub fn job_definition(&self) -> ::std::option::Option<&str> {
        self.job_definition.as_deref()
    }
}
impl DeregisterJobDefinitionInput {
    /// Creates a new builder-style object to manufacture [`DeregisterJobDefinitionInput`](crate::operation::deregister_job_definition::DeregisterJobDefinitionInput).
    pub fn builder() -> crate::operation::deregister_job_definition::builders::DeregisterJobDefinitionInputBuilder {
        crate::operation::deregister_job_definition::builders::DeregisterJobDefinitionInputBuilder::default()
    }
}

/// A builder for [`DeregisterJobDefinitionInput`](crate::operation::deregister_job_definition::DeregisterJobDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregisterJobDefinitionInputBuilder {
    pub(crate) job_definition: ::std::option::Option<::std::string::String>,
}
impl DeregisterJobDefinitionInputBuilder {
    /// <p>The name and revision (<code>name:revision</code>) or full Amazon Resource Name (ARN) of the job definition to deregister.</p>
    /// This field is required.
    pub fn job_definition(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_definition = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name and revision (<code>name:revision</code>) or full Amazon Resource Name (ARN) of the job definition to deregister.</p>
    pub fn set_job_definition(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_definition = input;
        self
    }
    /// <p>The name and revision (<code>name:revision</code>) or full Amazon Resource Name (ARN) of the job definition to deregister.</p>
    pub fn get_job_definition(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_definition
    }
    /// Consumes the builder and constructs a [`DeregisterJobDefinitionInput`](crate::operation::deregister_job_definition::DeregisterJobDefinitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::deregister_job_definition::DeregisterJobDefinitionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::deregister_job_definition::DeregisterJobDefinitionInput {
            job_definition: self.job_definition,
        })
    }
}
