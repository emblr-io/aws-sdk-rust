// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTestGridProjectInput {
    /// <p>Human-readable name of the Selenium testing project.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Human-readable description of the project.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The VPC security groups and subnets that are attached to a project.</p>
    pub vpc_config: ::std::option::Option<crate::types::TestGridVpcConfig>,
}
impl CreateTestGridProjectInput {
    /// <p>Human-readable name of the Selenium testing project.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Human-readable description of the project.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The VPC security groups and subnets that are attached to a project.</p>
    pub fn vpc_config(&self) -> ::std::option::Option<&crate::types::TestGridVpcConfig> {
        self.vpc_config.as_ref()
    }
}
impl CreateTestGridProjectInput {
    /// Creates a new builder-style object to manufacture [`CreateTestGridProjectInput`](crate::operation::create_test_grid_project::CreateTestGridProjectInput).
    pub fn builder() -> crate::operation::create_test_grid_project::builders::CreateTestGridProjectInputBuilder {
        crate::operation::create_test_grid_project::builders::CreateTestGridProjectInputBuilder::default()
    }
}

/// A builder for [`CreateTestGridProjectInput`](crate::operation::create_test_grid_project::CreateTestGridProjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTestGridProjectInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_config: ::std::option::Option<crate::types::TestGridVpcConfig>,
}
impl CreateTestGridProjectInputBuilder {
    /// <p>Human-readable name of the Selenium testing project.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Human-readable name of the Selenium testing project.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Human-readable name of the Selenium testing project.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Human-readable description of the project.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Human-readable description of the project.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Human-readable description of the project.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The VPC security groups and subnets that are attached to a project.</p>
    pub fn vpc_config(mut self, input: crate::types::TestGridVpcConfig) -> Self {
        self.vpc_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The VPC security groups and subnets that are attached to a project.</p>
    pub fn set_vpc_config(mut self, input: ::std::option::Option<crate::types::TestGridVpcConfig>) -> Self {
        self.vpc_config = input;
        self
    }
    /// <p>The VPC security groups and subnets that are attached to a project.</p>
    pub fn get_vpc_config(&self) -> &::std::option::Option<crate::types::TestGridVpcConfig> {
        &self.vpc_config
    }
    /// Consumes the builder and constructs a [`CreateTestGridProjectInput`](crate::operation::create_test_grid_project::CreateTestGridProjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_test_grid_project::CreateTestGridProjectInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_test_grid_project::CreateTestGridProjectInput {
            name: self.name,
            description: self.description,
            vpc_config: self.vpc_config,
        })
    }
}
