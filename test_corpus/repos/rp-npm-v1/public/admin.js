$(function () {
  var tpl = Handlebars.compile($('#row').html());
  $('#rows').html(tpl({ rows: window.ROWS }));
});
