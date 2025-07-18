// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <important>
/// <p>Amazon S3 Select is no longer available to new customers. Existing customers of Amazon S3 Select can continue to use the feature as usual. <a href="http://aws.amazon.com/blogs/storage/how-to-optimize-querying-your-data-in-amazon-s3/">Learn more</a></p>
/// </important>
/// <p>Describes the parameters for Select job types.</p>
/// <p>Learn <a href="http://aws.amazon.com/blogs/storage/how-to-optimize-querying-your-data-in-amazon-s3/">How to optimize querying your data in Amazon S3</a> using <a href="https://docs.aws.amazon.com/athena/latest/ug/what-is.html">Amazon Athena</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/transforming-objects.html">S3 Object Lambda</a>, or client-side filtering.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SelectParameters {
    /// <p>Describes the serialization format of the object.</p>
    pub input_serialization: ::std::option::Option<crate::types::InputSerialization>,
    /// <p>The type of the provided expression (for example, SQL).</p>
    pub expression_type: crate::types::ExpressionType,
    /// <important>
    /// <p>Amazon S3 Select is no longer available to new customers. Existing customers of Amazon S3 Select can continue to use the feature as usual. <a href="http://aws.amazon.com/blogs/storage/how-to-optimize-querying-your-data-in-amazon-s3/">Learn more</a></p>
    /// </important>
    /// <p>The expression that is used to query the object.</p>
    pub expression: ::std::string::String,
    /// <p>Describes how the results of the Select job are serialized.</p>
    pub output_serialization: ::std::option::Option<crate::types::OutputSerialization>,
}
impl SelectParameters {
    /// <p>Describes the serialization format of the object.</p>
    pub fn input_serialization(&self) -> ::std::option::Option<&crate::types::InputSerialization> {
        self.input_serialization.as_ref()
    }
    /// <p>The type of the provided expression (for example, SQL).</p>
    pub fn expression_type(&self) -> &crate::types::ExpressionType {
        &self.expression_type
    }
    /// <important>
    /// <p>Amazon S3 Select is no longer available to new customers. Existing customers of Amazon S3 Select can continue to use the feature as usual. <a href="http://aws.amazon.com/blogs/storage/how-to-optimize-querying-your-data-in-amazon-s3/">Learn more</a></p>
    /// </important>
    /// <p>The expression that is used to query the object.</p>
    pub fn expression(&self) -> &str {
        use std::ops::Deref;
        self.expression.deref()
    }
    /// <p>Describes how the results of the Select job are serialized.</p>
    pub fn output_serialization(&self) -> ::std::option::Option<&crate::types::OutputSerialization> {
        self.output_serialization.as_ref()
    }
}
impl SelectParameters {
    /// Creates a new builder-style object to manufacture [`SelectParameters`](crate::types::SelectParameters).
    pub fn builder() -> crate::types::builders::SelectParametersBuilder {
        crate::types::builders::SelectParametersBuilder::default()
    }
}

/// A builder for [`SelectParameters`](crate::types::SelectParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SelectParametersBuilder {
    pub(crate) input_serialization: ::std::option::Option<crate::types::InputSerialization>,
    pub(crate) expression_type: ::std::option::Option<crate::types::ExpressionType>,
    pub(crate) expression: ::std::option::Option<::std::string::String>,
    pub(crate) output_serialization: ::std::option::Option<crate::types::OutputSerialization>,
}
impl SelectParametersBuilder {
    /// <p>Describes the serialization format of the object.</p>
    /// This field is required.
    pub fn input_serialization(mut self, input: crate::types::InputSerialization) -> Self {
        self.input_serialization = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the serialization format of the object.</p>
    pub fn set_input_serialization(mut self, input: ::std::option::Option<crate::types::InputSerialization>) -> Self {
        self.input_serialization = input;
        self
    }
    /// <p>Describes the serialization format of the object.</p>
    pub fn get_input_serialization(&self) -> &::std::option::Option<crate::types::InputSerialization> {
        &self.input_serialization
    }
    /// <p>The type of the provided expression (for example, SQL).</p>
    /// This field is required.
    pub fn expression_type(mut self, input: crate::types::ExpressionType) -> Self {
        self.expression_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the provided expression (for example, SQL).</p>
    pub fn set_expression_type(mut self, input: ::std::option::Option<crate::types::ExpressionType>) -> Self {
        self.expression_type = input;
        self
    }
    /// <p>The type of the provided expression (for example, SQL).</p>
    pub fn get_expression_type(&self) -> &::std::option::Option<crate::types::ExpressionType> {
        &self.expression_type
    }
    /// <important>
    /// <p>Amazon S3 Select is no longer available to new customers. Existing customers of Amazon S3 Select can continue to use the feature as usual. <a href="http://aws.amazon.com/blogs/storage/how-to-optimize-querying-your-data-in-amazon-s3/">Learn more</a></p>
    /// </important>
    /// <p>The expression that is used to query the object.</p>
    /// This field is required.
    pub fn expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <important>
    /// <p>Amazon S3 Select is no longer available to new customers. Existing customers of Amazon S3 Select can continue to use the feature as usual. <a href="http://aws.amazon.com/blogs/storage/how-to-optimize-querying-your-data-in-amazon-s3/">Learn more</a></p>
    /// </important>
    /// <p>The expression that is used to query the object.</p>
    pub fn set_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression = input;
        self
    }
    /// <important>
    /// <p>Amazon S3 Select is no longer available to new customers. Existing customers of Amazon S3 Select can continue to use the feature as usual. <a href="http://aws.amazon.com/blogs/storage/how-to-optimize-querying-your-data-in-amazon-s3/">Learn more</a></p>
    /// </important>
    /// <p>The expression that is used to query the object.</p>
    pub fn get_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression
    }
    /// <p>Describes how the results of the Select job are serialized.</p>
    /// This field is required.
    pub fn output_serialization(mut self, input: crate::types::OutputSerialization) -> Self {
        self.output_serialization = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes how the results of the Select job are serialized.</p>
    pub fn set_output_serialization(mut self, input: ::std::option::Option<crate::types::OutputSerialization>) -> Self {
        self.output_serialization = input;
        self
    }
    /// <p>Describes how the results of the Select job are serialized.</p>
    pub fn get_output_serialization(&self) -> &::std::option::Option<crate::types::OutputSerialization> {
        &self.output_serialization
    }
    /// Consumes the builder and constructs a [`SelectParameters`](crate::types::SelectParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`expression_type`](crate::types::builders::SelectParametersBuilder::expression_type)
    /// - [`expression`](crate::types::builders::SelectParametersBuilder::expression)
    pub fn build(self) -> ::std::result::Result<crate::types::SelectParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SelectParameters {
            input_serialization: self.input_serialization,
            expression_type: self.expression_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "expression_type",
                    "expression_type was not specified but it is required when building SelectParameters",
                )
            })?,
            expression: self.expression.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "expression",
                    "expression was not specified but it is required when building SelectParameters",
                )
            })?,
            output_serialization: self.output_serialization,
        })
    }
}
