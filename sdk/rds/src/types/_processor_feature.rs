// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the processor features of a DB instance class.</p>
/// <p>To specify the number of CPU cores, use the <code>coreCount</code> feature name for the <code>Name</code> parameter. To specify the number of threads per core, use the <code>threadsPerCore</code> feature name for the <code>Name</code> parameter.</p>
/// <p>You can set the processor features of the DB instance class for a DB instance when you call one of the following actions:</p>
/// <ul>
/// <li>
/// <p><code>CreateDBInstance</code></p></li>
/// <li>
/// <p><code>ModifyDBInstance</code></p></li>
/// <li>
/// <p><code>RestoreDBInstanceFromDBSnapshot</code></p></li>
/// <li>
/// <p><code>RestoreDBInstanceFromS3</code></p></li>
/// <li>
/// <p><code>RestoreDBInstanceToPointInTime</code></p></li>
/// </ul>
/// <p>You can view the valid processor values for a particular instance class by calling the <code>DescribeOrderableDBInstanceOptions</code> action and specifying the instance class for the <code>DBInstanceClass</code> parameter.</p>
/// <p>In addition, you can use the following actions for DB instance class processor information:</p>
/// <ul>
/// <li>
/// <p><code>DescribeDBInstances</code></p></li>
/// <li>
/// <p><code>DescribeDBSnapshots</code></p></li>
/// <li>
/// <p><code>DescribeValidDBInstanceModifications</code></p></li>
/// </ul>
/// <p>If you call <code>DescribeDBInstances</code>, <code>ProcessorFeature</code> returns non-null values only if the following conditions are met:</p>
/// <ul>
/// <li>
/// <p>You are accessing an Oracle DB instance.</p></li>
/// <li>
/// <p>Your Oracle DB instance class supports configuring the number of CPU cores and threads per core.</p></li>
/// <li>
/// <p>The current number CPU cores and threads is set to a non-default value.</p></li>
/// </ul>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.html#USER_ConfigureProcessor"> Configuring the processor for a DB instance class in RDS for Oracle</a> in the <i>Amazon RDS User Guide. </i></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProcessorFeature {
    /// <p>The name of the processor feature. Valid names are <code>coreCount</code> and <code>threadsPerCore</code>.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The value of a processor feature.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl ProcessorFeature {
    /// <p>The name of the processor feature. Valid names are <code>coreCount</code> and <code>threadsPerCore</code>.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The value of a processor feature.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl ProcessorFeature {
    /// Creates a new builder-style object to manufacture [`ProcessorFeature`](crate::types::ProcessorFeature).
    pub fn builder() -> crate::types::builders::ProcessorFeatureBuilder {
        crate::types::builders::ProcessorFeatureBuilder::default()
    }
}

/// A builder for [`ProcessorFeature`](crate::types::ProcessorFeature).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProcessorFeatureBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl ProcessorFeatureBuilder {
    /// <p>The name of the processor feature. Valid names are <code>coreCount</code> and <code>threadsPerCore</code>.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the processor feature. Valid names are <code>coreCount</code> and <code>threadsPerCore</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the processor feature. Valid names are <code>coreCount</code> and <code>threadsPerCore</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The value of a processor feature.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of a processor feature.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of a processor feature.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`ProcessorFeature`](crate::types::ProcessorFeature).
    pub fn build(self) -> crate::types::ProcessorFeature {
        crate::types::ProcessorFeature {
            name: self.name,
            value: self.value,
        }
    }
}
