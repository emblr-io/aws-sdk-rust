// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDbParameterGroupInput {
    /// <p>The name of the DB parameter group. The name must be unique per customer and per region.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the DB parameter group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of the parameters that comprise the DB parameter group.</p>
    pub parameters: ::std::option::Option<crate::types::Parameters>,
    /// <p>A list of key-value pairs to associate with the DB parameter group.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateDbParameterGroupInput {
    /// <p>The name of the DB parameter group. The name must be unique per customer and per region.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the DB parameter group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A list of the parameters that comprise the DB parameter group.</p>
    pub fn parameters(&self) -> ::std::option::Option<&crate::types::Parameters> {
        self.parameters.as_ref()
    }
    /// <p>A list of key-value pairs to associate with the DB parameter group.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateDbParameterGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateDbParameterGroupInput`](crate::operation::create_db_parameter_group::CreateDbParameterGroupInput).
    pub fn builder() -> crate::operation::create_db_parameter_group::builders::CreateDbParameterGroupInputBuilder {
        crate::operation::create_db_parameter_group::builders::CreateDbParameterGroupInputBuilder::default()
    }
}

/// A builder for [`CreateDbParameterGroupInput`](crate::operation::create_db_parameter_group::CreateDbParameterGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDbParameterGroupInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<crate::types::Parameters>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateDbParameterGroupInputBuilder {
    /// <p>The name of the DB parameter group. The name must be unique per customer and per region.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DB parameter group. The name must be unique per customer and per region.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the DB parameter group. The name must be unique per customer and per region.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the DB parameter group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the DB parameter group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the DB parameter group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A list of the parameters that comprise the DB parameter group.</p>
    pub fn parameters(mut self, input: crate::types::Parameters) -> Self {
        self.parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of the parameters that comprise the DB parameter group.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<crate::types::Parameters>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>A list of the parameters that comprise the DB parameter group.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<crate::types::Parameters> {
        &self.parameters
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of key-value pairs to associate with the DB parameter group.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of key-value pairs to associate with the DB parameter group.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of key-value pairs to associate with the DB parameter group.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateDbParameterGroupInput`](crate::operation::create_db_parameter_group::CreateDbParameterGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_db_parameter_group::CreateDbParameterGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_db_parameter_group::CreateDbParameterGroupInput {
            name: self.name,
            description: self.description,
            parameters: self.parameters,
            tags: self.tags,
        })
    }
}
