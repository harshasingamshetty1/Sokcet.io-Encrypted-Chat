var socket = io();
socket.on('connect', function () {
  console.log('connected!')
  console.log('loaded', socket.id)
  d3.select('div#username_display').html(socket.id)
})
socket.on('decrypted_message', function (msg) {
  console.log(msg)

  var div_parent = d3.select('div#messages').append('div').attr('class', 'row').attr('id','single_message')

  var div_name = div_parent.append('div')
  var div_content = div_parent.append('div')

  div_name.attr('class','col-xs-3 text-right').attr('id', 'username_display')
  div_content.attr('class','col-xs-9').attr('id', 'message_display')

  div_name.html(msg.from)
  div_content.html(msg.msg)
  div_parent.node().scrollTop = 100000
})

var users = []

d3.select('input#user_input_search').on('keydown', function(){
  if(d3.event.keyCode === 13){
    console.log(d3.select(this).property('value'))
    send(d3.select(this).property('value'))
    d3.select(this).property('value','')
  }
})


function send(msg) {
  socket.emit('chat_message', {
    from: socket.id,
    to: 'all',
    msg: msg
  })
}
