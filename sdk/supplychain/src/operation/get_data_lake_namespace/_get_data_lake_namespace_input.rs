// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request parameters for GetDataLakeNamespace.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDataLakeNamespaceInput {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the namespace. Besides the namespaces user created, you can also specify the pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - Pre-defined namespace containing Amazon Web Services Supply Chain supported datasets, see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - Pre-defined namespace containing datasets with custom user-defined schemas.</p></li>
    /// </ul>
    pub name: ::std::option::Option<::std::string::String>,
}
impl GetDataLakeNamespaceInput {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The name of the namespace. Besides the namespaces user created, you can also specify the pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - Pre-defined namespace containing Amazon Web Services Supply Chain supported datasets, see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - Pre-defined namespace containing datasets with custom user-defined schemas.</p></li>
    /// </ul>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl GetDataLakeNamespaceInput {
    /// Creates a new builder-style object to manufacture [`GetDataLakeNamespaceInput`](crate::operation::get_data_lake_namespace::GetDataLakeNamespaceInput).
    pub fn builder() -> crate::operation::get_data_lake_namespace::builders::GetDataLakeNamespaceInputBuilder {
        crate::operation::get_data_lake_namespace::builders::GetDataLakeNamespaceInputBuilder::default()
    }
}

/// A builder for [`GetDataLakeNamespaceInput`](crate::operation::get_data_lake_namespace::GetDataLakeNamespaceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDataLakeNamespaceInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl GetDataLakeNamespaceInputBuilder {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The name of the namespace. Besides the namespaces user created, you can also specify the pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - Pre-defined namespace containing Amazon Web Services Supply Chain supported datasets, see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - Pre-defined namespace containing datasets with custom user-defined schemas.</p></li>
    /// </ul>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the namespace. Besides the namespaces user created, you can also specify the pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - Pre-defined namespace containing Amazon Web Services Supply Chain supported datasets, see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - Pre-defined namespace containing datasets with custom user-defined schemas.</p></li>
    /// </ul>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the namespace. Besides the namespaces user created, you can also specify the pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - Pre-defined namespace containing Amazon Web Services Supply Chain supported datasets, see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - Pre-defined namespace containing datasets with custom user-defined schemas.</p></li>
    /// </ul>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`GetDataLakeNamespaceInput`](crate::operation::get_data_lake_namespace::GetDataLakeNamespaceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_data_lake_namespace::GetDataLakeNamespaceInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_data_lake_namespace::GetDataLakeNamespaceInput {
            instance_id: self.instance_id,
            name: self.name,
        })
    }
}
