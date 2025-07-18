// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTableInput {
    /// <p>The Amazon Resource Name (ARN) of the table bucket associated with the table.</p>
    pub table_bucket_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the namespace the table is associated with.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The name of the table.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub table_arn: ::std::option::Option<::std::string::String>,
}
impl GetTableInput {
    /// <p>The Amazon Resource Name (ARN) of the table bucket associated with the table.</p>
    pub fn table_bucket_arn(&self) -> ::std::option::Option<&str> {
        self.table_bucket_arn.as_deref()
    }
    /// <p>The name of the namespace the table is associated with.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The name of the table.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub fn table_arn(&self) -> ::std::option::Option<&str> {
        self.table_arn.as_deref()
    }
}
impl GetTableInput {
    /// Creates a new builder-style object to manufacture [`GetTableInput`](crate::operation::get_table::GetTableInput).
    pub fn builder() -> crate::operation::get_table::builders::GetTableInputBuilder {
        crate::operation::get_table::builders::GetTableInputBuilder::default()
    }
}

/// A builder for [`GetTableInput`](crate::operation::get_table::GetTableInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTableInputBuilder {
    pub(crate) table_bucket_arn: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) table_arn: ::std::option::Option<::std::string::String>,
}
impl GetTableInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the table bucket associated with the table.</p>
    pub fn table_bucket_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_bucket_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table bucket associated with the table.</p>
    pub fn set_table_bucket_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_bucket_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table bucket associated with the table.</p>
    pub fn get_table_bucket_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_bucket_arn
    }
    /// <p>The name of the namespace the table is associated with.</p>
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the namespace the table is associated with.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The name of the namespace the table is associated with.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>The name of the table.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the table.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub fn table_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub fn set_table_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub fn get_table_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_arn
    }
    /// Consumes the builder and constructs a [`GetTableInput`](crate::operation::get_table::GetTableInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_table::GetTableInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_table::GetTableInput {
            table_bucket_arn: self.table_bucket_arn,
            namespace: self.namespace,
            name: self.name,
            table_arn: self.table_arn,
        })
    }
}
