// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutTablePolicyInput {
    /// <p>The Amazon Resource Name (ARN) of the table bucket that contains the table.</p>
    pub table_bucket_arn: ::std::option::Option<::std::string::String>,
    /// <p>The namespace associated with the table.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The name of the table.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The <code>JSON</code> that defines the policy.</p>
    pub resource_policy: ::std::option::Option<::std::string::String>,
}
impl PutTablePolicyInput {
    /// <p>The Amazon Resource Name (ARN) of the table bucket that contains the table.</p>
    pub fn table_bucket_arn(&self) -> ::std::option::Option<&str> {
        self.table_bucket_arn.as_deref()
    }
    /// <p>The namespace associated with the table.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The name of the table.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The <code>JSON</code> that defines the policy.</p>
    pub fn resource_policy(&self) -> ::std::option::Option<&str> {
        self.resource_policy.as_deref()
    }
}
impl PutTablePolicyInput {
    /// Creates a new builder-style object to manufacture [`PutTablePolicyInput`](crate::operation::put_table_policy::PutTablePolicyInput).
    pub fn builder() -> crate::operation::put_table_policy::builders::PutTablePolicyInputBuilder {
        crate::operation::put_table_policy::builders::PutTablePolicyInputBuilder::default()
    }
}

/// A builder for [`PutTablePolicyInput`](crate::operation::put_table_policy::PutTablePolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutTablePolicyInputBuilder {
    pub(crate) table_bucket_arn: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_policy: ::std::option::Option<::std::string::String>,
}
impl PutTablePolicyInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the table bucket that contains the table.</p>
    /// This field is required.
    pub fn table_bucket_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_bucket_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table bucket that contains the table.</p>
    pub fn set_table_bucket_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_bucket_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table bucket that contains the table.</p>
    pub fn get_table_bucket_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_bucket_arn
    }
    /// <p>The namespace associated with the table.</p>
    /// This field is required.
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace associated with the table.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace associated with the table.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>The name of the table.</p>
    /// This field is required.
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
    /// <p>The <code>JSON</code> that defines the policy.</p>
    /// This field is required.
    pub fn resource_policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>JSON</code> that defines the policy.</p>
    pub fn set_resource_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_policy = input;
        self
    }
    /// <p>The <code>JSON</code> that defines the policy.</p>
    pub fn get_resource_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_policy
    }
    /// Consumes the builder and constructs a [`PutTablePolicyInput`](crate::operation::put_table_policy::PutTablePolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_table_policy::PutTablePolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_table_policy::PutTablePolicyInput {
            table_bucket_arn: self.table_bucket_arn,
            namespace: self.namespace,
            name: self.name,
            resource_policy: self.resource_policy,
        })
    }
}
