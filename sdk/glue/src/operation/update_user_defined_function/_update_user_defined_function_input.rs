// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateUserDefinedFunctionInput {
    /// <p>The ID of the Data Catalog where the function to be updated is located. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the catalog database where the function to be updated is located.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the function.</p>
    pub function_name: ::std::option::Option<::std::string::String>,
    /// <p>A <code>FunctionInput</code> object that redefines the function in the Data Catalog.</p>
    pub function_input: ::std::option::Option<crate::types::UserDefinedFunctionInput>,
}
impl UpdateUserDefinedFunctionInput {
    /// <p>The ID of the Data Catalog where the function to be updated is located. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>The name of the catalog database where the function to be updated is located.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The name of the function.</p>
    pub fn function_name(&self) -> ::std::option::Option<&str> {
        self.function_name.as_deref()
    }
    /// <p>A <code>FunctionInput</code> object that redefines the function in the Data Catalog.</p>
    pub fn function_input(&self) -> ::std::option::Option<&crate::types::UserDefinedFunctionInput> {
        self.function_input.as_ref()
    }
}
impl UpdateUserDefinedFunctionInput {
    /// Creates a new builder-style object to manufacture [`UpdateUserDefinedFunctionInput`](crate::operation::update_user_defined_function::UpdateUserDefinedFunctionInput).
    pub fn builder() -> crate::operation::update_user_defined_function::builders::UpdateUserDefinedFunctionInputBuilder {
        crate::operation::update_user_defined_function::builders::UpdateUserDefinedFunctionInputBuilder::default()
    }
}

/// A builder for [`UpdateUserDefinedFunctionInput`](crate::operation::update_user_defined_function::UpdateUserDefinedFunctionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateUserDefinedFunctionInputBuilder {
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) function_name: ::std::option::Option<::std::string::String>,
    pub(crate) function_input: ::std::option::Option<crate::types::UserDefinedFunctionInput>,
}
impl UpdateUserDefinedFunctionInputBuilder {
    /// <p>The ID of the Data Catalog where the function to be updated is located. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Data Catalog where the function to be updated is located. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The ID of the Data Catalog where the function to be updated is located. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>The name of the catalog database where the function to be updated is located.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the catalog database where the function to be updated is located.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The name of the catalog database where the function to be updated is located.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The name of the function.</p>
    /// This field is required.
    pub fn function_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the function.</p>
    pub fn set_function_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function_name = input;
        self
    }
    /// <p>The name of the function.</p>
    pub fn get_function_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.function_name
    }
    /// <p>A <code>FunctionInput</code> object that redefines the function in the Data Catalog.</p>
    /// This field is required.
    pub fn function_input(mut self, input: crate::types::UserDefinedFunctionInput) -> Self {
        self.function_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>FunctionInput</code> object that redefines the function in the Data Catalog.</p>
    pub fn set_function_input(mut self, input: ::std::option::Option<crate::types::UserDefinedFunctionInput>) -> Self {
        self.function_input = input;
        self
    }
    /// <p>A <code>FunctionInput</code> object that redefines the function in the Data Catalog.</p>
    pub fn get_function_input(&self) -> &::std::option::Option<crate::types::UserDefinedFunctionInput> {
        &self.function_input
    }
    /// Consumes the builder and constructs a [`UpdateUserDefinedFunctionInput`](crate::operation::update_user_defined_function::UpdateUserDefinedFunctionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_user_defined_function::UpdateUserDefinedFunctionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_user_defined_function::UpdateUserDefinedFunctionInput {
            catalog_id: self.catalog_id,
            database_name: self.database_name,
            function_name: self.function_name,
            function_input: self.function_input,
        })
    }
}
