// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::unnecessary_wraps)]
pub fn de_put_metric_filter_http_error(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<crate::operation::put_metric_filter::PutMetricFilterOutput, crate::operation::put_metric_filter::PutMetricFilterError> {
    #[allow(unused_mut)]
    let mut generic_builder = crate::protocol_serde::parse_http_error_metadata(_response_status, _response_headers, _response_body)
        .map_err(crate::operation::put_metric_filter::PutMetricFilterError::unhandled)?;
    generic_builder = ::aws_types::request_id::apply_request_id(generic_builder, _response_headers);
    let generic = generic_builder.build();
    let error_code = match generic.code() {
        Some(code) => code,
        None => return Err(crate::operation::put_metric_filter::PutMetricFilterError::unhandled(generic)),
    };

    let _error_message = generic.message().map(|msg| msg.to_owned());
    Err(match error_code {
        "InvalidOperationException" => crate::operation::put_metric_filter::PutMetricFilterError::InvalidOperationException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::InvalidOperationExceptionBuilder::default();
                output = crate::protocol_serde::shape_invalid_operation_exception::de_invalid_operation_exception_json_err(_response_body, output)
                    .map_err(crate::operation::put_metric_filter::PutMetricFilterError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "InvalidParameterException" => crate::operation::put_metric_filter::PutMetricFilterError::InvalidParameterException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::InvalidParameterExceptionBuilder::default();
                output = crate::protocol_serde::shape_invalid_parameter_exception::de_invalid_parameter_exception_json_err(_response_body, output)
                    .map_err(crate::operation::put_metric_filter::PutMetricFilterError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "LimitExceededException" => crate::operation::put_metric_filter::PutMetricFilterError::LimitExceededException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::LimitExceededExceptionBuilder::default();
                output = crate::protocol_serde::shape_limit_exceeded_exception::de_limit_exceeded_exception_json_err(_response_body, output)
                    .map_err(crate::operation::put_metric_filter::PutMetricFilterError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "OperationAbortedException" => crate::operation::put_metric_filter::PutMetricFilterError::OperationAbortedException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::OperationAbortedExceptionBuilder::default();
                output = crate::protocol_serde::shape_operation_aborted_exception::de_operation_aborted_exception_json_err(_response_body, output)
                    .map_err(crate::operation::put_metric_filter::PutMetricFilterError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ResourceNotFoundException" => crate::operation::put_metric_filter::PutMetricFilterError::ResourceNotFoundException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ResourceNotFoundExceptionBuilder::default();
                output = crate::protocol_serde::shape_resource_not_found_exception::de_resource_not_found_exception_json_err(_response_body, output)
                    .map_err(crate::operation::put_metric_filter::PutMetricFilterError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ServiceUnavailableException" => crate::operation::put_metric_filter::PutMetricFilterError::ServiceUnavailableException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ServiceUnavailableExceptionBuilder::default();
                output =
                    crate::protocol_serde::shape_service_unavailable_exception::de_service_unavailable_exception_json_err(_response_body, output)
                        .map_err(crate::operation::put_metric_filter::PutMetricFilterError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        _ => crate::operation::put_metric_filter::PutMetricFilterError::generic(generic),
    })
}

#[allow(clippy::unnecessary_wraps)]
pub fn de_put_metric_filter_http_response(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<crate::operation::put_metric_filter::PutMetricFilterOutput, crate::operation::put_metric_filter::PutMetricFilterError> {
    Ok({
        #[allow(unused_mut)]
        let mut output = crate::operation::put_metric_filter::builders::PutMetricFilterOutputBuilder::default();
        output._set_request_id(::aws_types::request_id::RequestId::request_id(_response_headers).map(str::to_string));
        output.build()
    })
}

pub fn ser_put_metric_filter_input(
    input: &crate::operation::put_metric_filter::PutMetricFilterInput,
) -> ::std::result::Result<::aws_smithy_types::body::SdkBody, ::aws_smithy_types::error::operation::SerializationError> {
    let mut out = String::new();
    let mut object = ::aws_smithy_json::serialize::JsonObjectWriter::new(&mut out);
    crate::protocol_serde::shape_put_metric_filter_input::ser_put_metric_filter_input_input(&mut object, input)?;
    object.finish();
    Ok(::aws_smithy_types::body::SdkBody::from(out))
}
