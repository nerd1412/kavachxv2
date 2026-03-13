export default function Card({ title, children, action, className = '', style = {} }) {
  return (
    <div className={'card ' + className} style={style}>
      {title !== undefined && (
        <div className="card-header">
          <span className="card-title">{title}</span>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className="card-body">{children}</div>
    </div>
  )
}
