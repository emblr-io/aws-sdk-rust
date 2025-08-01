// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Identifies a scanned resource. This is used with the <code>ListResourceScanRelatedResources</code> API action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScannedResourceIdentifier {
    /// <p>The type of the resource, such as <code>AWS::DynamoDB::Table</code>. For the list of supported resources, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-supported-resources.html">Resource type support for imports and drift detection</a> In the <i>CloudFormation User Guide</i>.</p>
    pub resource_type: ::std::option::Option<::std::string::String>,
    /// <p>A list of up to 256 key-value pairs that identifies the scanned resource. The key is the name of one of the primary identifiers for the resource. (Primary identifiers are specified in the <code>primaryIdentifier</code> list in the resource schema.) The value is the value of that primary identifier. For example, for a <code>AWS::DynamoDB::Table</code> resource, the primary identifiers is <code>TableName</code> so the key-value pair could be <code>"TableName": "MyDDBTable"</code>. For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/resource-type-schema.html#schema-properties-primaryidentifier">primaryIdentifier</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub resource_identifier: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ScannedResourceIdentifier {
    /// <p>The type of the resource, such as <code>AWS::DynamoDB::Table</code>. For the list of supported resources, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-supported-resources.html">Resource type support for imports and drift detection</a> In the <i>CloudFormation User Guide</i>.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&str> {
        self.resource_type.as_deref()
    }
    /// <p>A list of up to 256 key-value pairs that identifies the scanned resource. The key is the name of one of the primary identifiers for the resource. (Primary identifiers are specified in the <code>primaryIdentifier</code> list in the resource schema.) The value is the value of that primary identifier. For example, for a <code>AWS::DynamoDB::Table</code> resource, the primary identifiers is <code>TableName</code> so the key-value pair could be <code>"TableName": "MyDDBTable"</code>. For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/resource-type-schema.html#schema-properties-primaryidentifier">primaryIdentifier</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub fn resource_identifier(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.resource_identifier.as_ref()
    }
}
impl ScannedResourceIdentifier {
    /// Creates a new builder-style object to manufacture [`ScannedResourceIdentifier`](crate::types::ScannedResourceIdentifier).
    pub fn builder() -> crate::types::builders::ScannedResourceIdentifierBuilder {
        crate::types::builders::ScannedResourceIdentifierBuilder::default()
    }
}

/// A builder for [`ScannedResourceIdentifier`](crate::types::ScannedResourceIdentifier).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScannedResourceIdentifierBuilder {
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) resource_identifier: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ScannedResourceIdentifierBuilder {
    /// <p>The type of the resource, such as <code>AWS::DynamoDB::Table</code>. For the list of supported resources, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-supported-resources.html">Resource type support for imports and drift detection</a> In the <i>CloudFormation User Guide</i>.</p>
    /// This field is required.
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the resource, such as <code>AWS::DynamoDB::Table</code>. For the list of supported resources, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-supported-resources.html">Resource type support for imports and drift detection</a> In the <i>CloudFormation User Guide</i>.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of the resource, such as <code>AWS::DynamoDB::Table</code>. For the list of supported resources, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-supported-resources.html">Resource type support for imports and drift detection</a> In the <i>CloudFormation User Guide</i>.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// Adds a key-value pair to `resource_identifier`.
    ///
    /// To override the contents of this collection use [`set_resource_identifier`](Self::set_resource_identifier).
    ///
    /// <p>A list of up to 256 key-value pairs that identifies the scanned resource. The key is the name of one of the primary identifiers for the resource. (Primary identifiers are specified in the <code>primaryIdentifier</code> list in the resource schema.) The value is the value of that primary identifier. For example, for a <code>AWS::DynamoDB::Table</code> resource, the primary identifiers is <code>TableName</code> so the key-value pair could be <code>"TableName": "MyDDBTable"</code>. For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/resource-type-schema.html#schema-properties-primaryidentifier">primaryIdentifier</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub fn resource_identifier(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.resource_identifier.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.resource_identifier = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of up to 256 key-value pairs that identifies the scanned resource. The key is the name of one of the primary identifiers for the resource. (Primary identifiers are specified in the <code>primaryIdentifier</code> list in the resource schema.) The value is the value of that primary identifier. For example, for a <code>AWS::DynamoDB::Table</code> resource, the primary identifiers is <code>TableName</code> so the key-value pair could be <code>"TableName": "MyDDBTable"</code>. For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/resource-type-schema.html#schema-properties-primaryidentifier">primaryIdentifier</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub fn set_resource_identifier(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.resource_identifier = input;
        self
    }
    /// <p>A list of up to 256 key-value pairs that identifies the scanned resource. The key is the name of one of the primary identifiers for the resource. (Primary identifiers are specified in the <code>primaryIdentifier</code> list in the resource schema.) The value is the value of that primary identifier. For example, for a <code>AWS::DynamoDB::Table</code> resource, the primary identifiers is <code>TableName</code> so the key-value pair could be <code>"TableName": "MyDDBTable"</code>. For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/resource-type-schema.html#schema-properties-primaryidentifier">primaryIdentifier</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub fn get_resource_identifier(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.resource_identifier
    }
    /// Consumes the builder and constructs a [`ScannedResourceIdentifier`](crate::types::ScannedResourceIdentifier).
    pub fn build(self) -> crate::types::ScannedResourceIdentifier {
        crate::types::ScannedResourceIdentifier {
            resource_type: self.resource_type,
            resource_identifier: self.resource_identifier,
        }
    }
}
