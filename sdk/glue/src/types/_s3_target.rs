// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a data store in Amazon Simple Storage Service (Amazon S3).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3Target {
    /// <p>The path to the Amazon S3 target.</p>
    pub path: ::std::option::Option<::std::string::String>,
    /// <p>A list of glob patterns used to exclude from the crawl. For more information, see <a href="https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html">Catalog Tables with a Crawler</a>.</p>
    pub exclusions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of a connection which allows a job or crawler to access data in Amazon S3 within an Amazon Virtual Private Cloud environment (Amazon VPC).</p>
    pub connection_name: ::std::option::Option<::std::string::String>,
    /// <p>Sets the number of files in each leaf folder to be crawled when crawling sample files in a dataset. If not set, all the files are crawled. A valid value is an integer between 1 and 249.</p>
    pub sample_size: ::std::option::Option<i32>,
    /// <p>A valid Amazon SQS ARN. For example, <code>arn:aws:sqs:region:account:sqs</code>.</p>
    pub event_queue_arn: ::std::option::Option<::std::string::String>,
    /// <p>A valid Amazon dead-letter SQS ARN. For example, <code>arn:aws:sqs:region:account:deadLetterQueue</code>.</p>
    pub dlq_event_queue_arn: ::std::option::Option<::std::string::String>,
}
impl S3Target {
    /// <p>The path to the Amazon S3 target.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
    /// <p>A list of glob patterns used to exclude from the crawl. For more information, see <a href="https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html">Catalog Tables with a Crawler</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.exclusions.is_none()`.
    pub fn exclusions(&self) -> &[::std::string::String] {
        self.exclusions.as_deref().unwrap_or_default()
    }
    /// <p>The name of a connection which allows a job or crawler to access data in Amazon S3 within an Amazon Virtual Private Cloud environment (Amazon VPC).</p>
    pub fn connection_name(&self) -> ::std::option::Option<&str> {
        self.connection_name.as_deref()
    }
    /// <p>Sets the number of files in each leaf folder to be crawled when crawling sample files in a dataset. If not set, all the files are crawled. A valid value is an integer between 1 and 249.</p>
    pub fn sample_size(&self) -> ::std::option::Option<i32> {
        self.sample_size
    }
    /// <p>A valid Amazon SQS ARN. For example, <code>arn:aws:sqs:region:account:sqs</code>.</p>
    pub fn event_queue_arn(&self) -> ::std::option::Option<&str> {
        self.event_queue_arn.as_deref()
    }
    /// <p>A valid Amazon dead-letter SQS ARN. For example, <code>arn:aws:sqs:region:account:deadLetterQueue</code>.</p>
    pub fn dlq_event_queue_arn(&self) -> ::std::option::Option<&str> {
        self.dlq_event_queue_arn.as_deref()
    }
}
impl S3Target {
    /// Creates a new builder-style object to manufacture [`S3Target`](crate::types::S3Target).
    pub fn builder() -> crate::types::builders::S3TargetBuilder {
        crate::types::builders::S3TargetBuilder::default()
    }
}

/// A builder for [`S3Target`](crate::types::S3Target).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3TargetBuilder {
    pub(crate) path: ::std::option::Option<::std::string::String>,
    pub(crate) exclusions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) connection_name: ::std::option::Option<::std::string::String>,
    pub(crate) sample_size: ::std::option::Option<i32>,
    pub(crate) event_queue_arn: ::std::option::Option<::std::string::String>,
    pub(crate) dlq_event_queue_arn: ::std::option::Option<::std::string::String>,
}
impl S3TargetBuilder {
    /// <p>The path to the Amazon S3 target.</p>
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the Amazon S3 target.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>The path to the Amazon S3 target.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// Appends an item to `exclusions`.
    ///
    /// To override the contents of this collection use [`set_exclusions`](Self::set_exclusions).
    ///
    /// <p>A list of glob patterns used to exclude from the crawl. For more information, see <a href="https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html">Catalog Tables with a Crawler</a>.</p>
    pub fn exclusions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.exclusions.unwrap_or_default();
        v.push(input.into());
        self.exclusions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of glob patterns used to exclude from the crawl. For more information, see <a href="https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html">Catalog Tables with a Crawler</a>.</p>
    pub fn set_exclusions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.exclusions = input;
        self
    }
    /// <p>A list of glob patterns used to exclude from the crawl. For more information, see <a href="https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html">Catalog Tables with a Crawler</a>.</p>
    pub fn get_exclusions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.exclusions
    }
    /// <p>The name of a connection which allows a job or crawler to access data in Amazon S3 within an Amazon Virtual Private Cloud environment (Amazon VPC).</p>
    pub fn connection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a connection which allows a job or crawler to access data in Amazon S3 within an Amazon Virtual Private Cloud environment (Amazon VPC).</p>
    pub fn set_connection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_name = input;
        self
    }
    /// <p>The name of a connection which allows a job or crawler to access data in Amazon S3 within an Amazon Virtual Private Cloud environment (Amazon VPC).</p>
    pub fn get_connection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_name
    }
    /// <p>Sets the number of files in each leaf folder to be crawled when crawling sample files in a dataset. If not set, all the files are crawled. A valid value is an integer between 1 and 249.</p>
    pub fn sample_size(mut self, input: i32) -> Self {
        self.sample_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets the number of files in each leaf folder to be crawled when crawling sample files in a dataset. If not set, all the files are crawled. A valid value is an integer between 1 and 249.</p>
    pub fn set_sample_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.sample_size = input;
        self
    }
    /// <p>Sets the number of files in each leaf folder to be crawled when crawling sample files in a dataset. If not set, all the files are crawled. A valid value is an integer between 1 and 249.</p>
    pub fn get_sample_size(&self) -> &::std::option::Option<i32> {
        &self.sample_size
    }
    /// <p>A valid Amazon SQS ARN. For example, <code>arn:aws:sqs:region:account:sqs</code>.</p>
    pub fn event_queue_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_queue_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A valid Amazon SQS ARN. For example, <code>arn:aws:sqs:region:account:sqs</code>.</p>
    pub fn set_event_queue_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_queue_arn = input;
        self
    }
    /// <p>A valid Amazon SQS ARN. For example, <code>arn:aws:sqs:region:account:sqs</code>.</p>
    pub fn get_event_queue_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_queue_arn
    }
    /// <p>A valid Amazon dead-letter SQS ARN. For example, <code>arn:aws:sqs:region:account:deadLetterQueue</code>.</p>
    pub fn dlq_event_queue_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dlq_event_queue_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A valid Amazon dead-letter SQS ARN. For example, <code>arn:aws:sqs:region:account:deadLetterQueue</code>.</p>
    pub fn set_dlq_event_queue_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dlq_event_queue_arn = input;
        self
    }
    /// <p>A valid Amazon dead-letter SQS ARN. For example, <code>arn:aws:sqs:region:account:deadLetterQueue</code>.</p>
    pub fn get_dlq_event_queue_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dlq_event_queue_arn
    }
    /// Consumes the builder and constructs a [`S3Target`](crate::types::S3Target).
    pub fn build(self) -> crate::types::S3Target {
        crate::types::S3Target {
            path: self.path,
            exclusions: self.exclusions,
            connection_name: self.connection_name,
            sample_size: self.sample_size,
            event_queue_arn: self.event_queue_arn,
            dlq_event_queue_arn: self.dlq_event_queue_arn,
        }
    }
}
